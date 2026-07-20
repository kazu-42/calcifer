//! Bounded guardian-owned WebSocket worker for the observe-only monitor.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(test)]
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tungstenite::client::client_with_config;
use tungstenite::error::ProtocolError;
use tungstenite::handshake::HandshakeError;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Error as WebSocketError, Message, WebSocket};

use super::super::supervisor::ConnectedMonitorSession;
use super::super::{CodexUsage, CodexUsageError};
use super::{MonitorAction, MonitorCommand, MonitorError, MonitorProtocol};

const WEBSOCKET_ENDPOINT: &str = "ws://localhost/rpc";
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const READ_BUFFER_BYTES: usize = 8 * 1024;
const MAX_WRITE_BUFFER_BYTES: usize = 64 * 1024;
const MAX_OUTBOUND_COMMAND_BYTES: usize = 4 * 1024;

const DEFAULT_IO_SLICE: Duration = Duration::from_millis(250);
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

const WORKER_STARTING: u8 = 0;
const WORKER_RUNNING: u8 = 1;
const WORKER_STOPPING: u8 = 2;
const WORKER_FAILED: u8 = 3;
const WORKER_STOPPED: u8 = 4;
const WORKER_FORCED_STOPPING: u8 = 5;

enum WorkerRunError {
    Stopped,
    Failed(MonitorTransportError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MonitorTransportError {
    InvalidArgument,
    Handshake,
    Protocol,
    Authentication,
    Provider,
    Unsupported,
    Timeout,
    Transport,
    Worker,
    AppServer,
}

impl fmt::Display for MonitorTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "the Codex monitor transport arguments were invalid",
            Self::Handshake => "the Codex monitor WebSocket handshake failed",
            Self::Protocol => "the Codex monitor transport protocol failed",
            Self::Authentication => "the Codex monitor profile is not authenticated",
            Self::Provider => "the Codex monitor provider request failed",
            Self::Unsupported => "the Codex monitor contract is unsupported",
            Self::Timeout => "the Codex monitor transport timed out",
            Self::Transport => "the Codex monitor connection ended unexpectedly",
            Self::Worker => "the Codex monitor worker failed",
            Self::AppServer => "the supervised Codex App Server is not live",
        })
    }
}

impl std::error::Error for MonitorTransportError {}

#[derive(Clone, Copy)]
struct MonitorTiming {
    io_slice: Duration,
    startup_timeout: Duration,
    request_timeout: Duration,
    poll_interval: Duration,
}

impl MonitorTiming {
    const DEFAULT: Self = Self {
        io_slice: DEFAULT_IO_SLICE,
        startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        request_timeout: DEFAULT_REQUEST_TIMEOUT,
        poll_interval: DEFAULT_POLL_INTERVAL,
    };

    fn validate(self) -> Result<Self, MonitorTransportError> {
        if self.io_slice.is_zero()
            || self.startup_timeout.is_zero()
            || self.request_timeout.is_zero()
            || self.poll_interval.is_zero()
        {
            return Err(MonitorTransportError::InvalidArgument);
        }
        Ok(self)
    }
}

/// A bounded usage-limit observation. Debug output is deliberately redacted.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct UsageLimitSignal {
    thread_id: String,
    turn_id: String,
}

impl UsageLimitSignal {
    pub(super) fn thread_id(&self) -> &str {
        &self.thread_id
    }

    pub(super) fn turn_id(&self) -> &str {
        &self.turn_id
    }
}

impl fmt::Debug for UsageLimitSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UsageLimitSignal(<redacted>)")
    }
}

struct MonitorShared {
    lifecycle: AtomicU8,
    latest_usage: Mutex<Option<CodexUsage>>,
    usage_limit: Mutex<Option<UsageLimitSignal>>,
    failure: Mutex<Option<MonitorTransportError>>,
}

impl MonitorShared {
    fn new() -> Self {
        Self {
            lifecycle: AtomicU8::new(WORKER_STARTING),
            latest_usage: Mutex::new(None),
            usage_limit: Mutex::new(None),
            failure: Mutex::new(None),
        }
    }

    fn claim_failure(&self, error: MonitorTransportError) -> WorkerRunError {
        let Ok(mut failure) = self.failure.lock() else {
            let _ = self.lifecycle.compare_exchange(
                WORKER_STARTING,
                WORKER_FAILED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            let _ = self.lifecycle.compare_exchange(
                WORKER_RUNNING,
                WORKER_FAILED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return match self.lifecycle.load(Ordering::Acquire) {
                WORKER_STOPPING | WORKER_FORCED_STOPPING | WORKER_STOPPED => {
                    WorkerRunError::Stopped
                }
                _ => WorkerRunError::Failed(MonitorTransportError::Worker),
            };
        };
        loop {
            let lifecycle = self.lifecycle.load(Ordering::Acquire);
            match lifecycle {
                WORKER_STARTING | WORKER_RUNNING => {
                    if self
                        .lifecycle
                        .compare_exchange(
                            lifecycle,
                            WORKER_FAILED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // Publish the causal error exactly once while holding
                        // the same mutex used by `failure()`. Readers that see
                        // WORKER_FAILED therefore block until this value is
                        // available, and a later failure cannot reclassify it.
                        *failure = Some(error);
                        return WorkerRunError::Failed(error);
                    }
                }
                WORKER_STOPPING | WORKER_FORCED_STOPPING | WORKER_STOPPED => {
                    return WorkerRunError::Stopped;
                }
                WORKER_FAILED => {
                    return WorkerRunError::Failed(
                        failure.unwrap_or(MonitorTransportError::Worker),
                    );
                }
                _ => return WorkerRunError::Failed(MonitorTransportError::Worker),
            }
        }
    }

    fn failure(&self) -> MonitorTransportError {
        self.failure
            .lock()
            .ok()
            .and_then(|failure| *failure)
            .unwrap_or(MonitorTransportError::Worker)
    }
}

/// One persistent, typed, observe-only connection to an already-validated App
/// Server socket. Production construction retains the exact App child/socket
/// aggregate for the complete worker lifetime.
#[must_use = "the Codex monitor worker must be explicitly shut down and joined"]
pub(super) struct MonitorWorker {
    control: UnixStream,
    shared: Arc<MonitorShared>,
    startup: Receiver<Result<(), MonitorTransportError>>,
    startup_result: Option<Result<(), MonitorTransportError>>,
    worker: Option<JoinHandle<Result<(), MonitorTransportError>>>,
    timing: MonitorTiming,
    session: Option<ConnectedMonitorSession>,
}

#[must_use = "monitor startup failure retains the exact App Server session"]
pub(super) struct MonitorStartFailure {
    session: ConnectedMonitorSession,
    error: MonitorTransportError,
}

impl MonitorStartFailure {
    pub(super) const fn error(&self) -> MonitorTransportError {
        self.error
    }

    pub(super) fn into_session(self) -> ConnectedMonitorSession {
        self.session
    }
}

impl fmt::Debug for MonitorStartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.session;
        formatter
            .debug_struct("MonitorStartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

fn finalize_startup_readiness<F>(
    result: Result<(), MonitorTransportError>,
    ensure_app_live: F,
) -> Result<(), MonitorTransportError>
where
    F: FnOnce() -> Result<(), MonitorTransportError>,
{
    result.and_then(|()| ensure_app_live())
}

impl MonitorWorker {
    pub(super) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.control.as_fd())?;
        if let Some(session) = self.session.as_ref() {
            session.append_forbidden_descriptors(forbidden)?;
        }
        Ok(())
    }

    pub(super) fn spawn_connected(
        mut session: ConnectedMonitorSession,
    ) -> Result<Self, Box<MonitorStartFailure>> {
        let (stream, capability) = match session.take_transport() {
            Ok(parts) => parts,
            Err(_) => {
                return Err(Box::new(MonitorStartFailure {
                    session,
                    error: MonitorTransportError::InvalidArgument,
                }));
            }
        };
        let (protocol, initialize) = match MonitorProtocol::start_pinned(capability) {
            Ok(protocol) => protocol,
            Err(_) => {
                return Err(Box::new(MonitorStartFailure {
                    session,
                    error: MonitorTransportError::InvalidArgument,
                }));
            }
        };
        Self::spawn_connected_owned(
            stream,
            protocol,
            initialize,
            MonitorTiming::DEFAULT,
            session,
        )
        .map_err(|(error, session)| Box::new(MonitorStartFailure { session, error }))
    }

    fn spawn_connected_owned<O>(
        stream: UnixStream,
        protocol: MonitorProtocol,
        initialize: MonitorCommand,
        timing: MonitorTiming,
        session: O,
    ) -> Result<Self, (MonitorTransportError, O)>
    where
        O: Into<Option<ConnectedMonitorSession>>,
    {
        let timing = match timing.validate() {
            Ok(timing) => timing,
            Err(error) => return Err((error, session)),
        };
        if !matches!(initialize, MonitorCommand::Initialize { .. }) {
            return Err((MonitorTransportError::InvalidArgument, session));
        }
        if stream.set_nonblocking(false).is_err() {
            return Err((MonitorTransportError::Transport, session));
        }
        let control = match stream.try_clone() {
            Ok(control) => control,
            Err(_) => return Err((MonitorTransportError::Transport, session)),
        };
        let shared = Arc::new(MonitorShared::new());
        let thread_shared = Arc::clone(&shared);
        let (startup_sender, startup) = mpsc::sync_channel(1);
        let worker = match thread::Builder::new()
            .name("calcifer-codex-usage-monitor".to_owned())
            .spawn(move || {
                let result = run_worker(
                    stream,
                    protocol,
                    initialize,
                    timing,
                    &thread_shared,
                    &startup_sender,
                );
                finalize_worker_run(result, &thread_shared, &startup_sender)
            }) {
            Ok(worker) => worker,
            Err(_) => return Err((MonitorTransportError::Worker, session)),
        };

        Ok(Self {
            control,
            shared,
            startup,
            startup_result: None,
            worker: Some(worker),
            timing,
            session: session.into(),
        })
    }

    /// Waits until the initialize gate and first authoritative usage read both
    /// succeed. A timeout starts teardown rather than leaving a detached worker.
    #[cfg(test)]
    pub(super) fn wait_until_ready(&mut self) -> Result<(), MonitorTransportError> {
        if let Some(result) = self.startup_result {
            return match result {
                Ok(()) => self.ensure_live(),
                Err(error) => Err(error),
            };
        }
        let wait = self
            .timing
            .startup_timeout
            .checked_add(self.timing.io_slice)
            .ok_or(MonitorTransportError::InvalidArgument)?;
        let result = match self.startup.recv_timeout(wait) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(MonitorTransportError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(self.shared.failure()),
        };
        let mut result =
            if result.is_ok() && self.shared.lifecycle.load(Ordering::Acquire) != WORKER_RUNNING {
                Err(self.shared.failure())
            } else {
                result
            };
        result = finalize_startup_readiness(result, || self.ensure_app_live());
        if result.is_err() {
            self.request_stop();
        }
        self.startup_result = Some(result);
        result
    }

    /// Nonblocking startup observation used while the guardian must continue
    /// draining the TUI PTY. `None` means only that the authoritative initial
    /// usage read has not completed yet; worker/App loss is still fatal.
    pub(super) fn poll_ready(&mut self) -> Result<Option<()>, MonitorTransportError> {
        if let Some(result) = self.startup_result {
            return match result {
                Ok(()) => self.ensure_live().map(|()| Some(())),
                Err(error) => Err(error),
            };
        }
        let result = match self.startup.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(self.shared.failure())),
        };
        let Some(mut result) = result else {
            if self.worker.as_ref().is_none_or(JoinHandle::is_finished)
                || matches!(
                    self.shared.lifecycle.load(Ordering::Acquire),
                    WORKER_FAILED | WORKER_STOPPED
                )
            {
                return Err(self.shared.failure());
            }
            self.ensure_app_live()?;
            return Ok(None);
        };
        if result.is_ok() && self.shared.lifecycle.load(Ordering::Acquire) != WORKER_RUNNING {
            result = Err(self.shared.failure());
        }
        result = finalize_startup_readiness(result, || self.ensure_app_live());
        if result.is_err() {
            self.request_stop();
        }
        self.startup_result = Some(result);
        result.map(|()| Some(()))
    }

    /// Returns a clone only while startup succeeded and the worker is still
    /// live. A failure can therefore never revive an older snapshot.
    pub(super) fn latest_usage(&self) -> Option<CodexUsage> {
        if self.startup_result != Some(Ok(()))
            || self.shared.lifecycle.load(Ordering::Acquire) != WORKER_RUNNING
        {
            return None;
        }
        let snapshot = self.shared.latest_usage.lock().ok()?.clone();
        if self.shared.lifecycle.load(Ordering::Acquire) == WORKER_RUNNING {
            snapshot
        } else {
            None
        }
    }

    pub(super) fn take_usage_limit(
        &self,
    ) -> Result<Option<UsageLimitSignal>, MonitorTransportError> {
        if self.shared.lifecycle.load(Ordering::Acquire) != WORKER_RUNNING {
            return Err(self.shared.failure());
        }
        let signal = self
            .shared
            .usage_limit
            .lock()
            .map(|mut signal| signal.take())
            .map_err(|_| MonitorTransportError::Worker)?;
        if self.shared.lifecycle.load(Ordering::Acquire) == WORKER_RUNNING {
            Ok(signal)
        } else {
            Err(self.shared.failure())
        }
    }

    pub(super) fn ensure_live(&mut self) -> Result<(), MonitorTransportError> {
        match self.startup_result {
            Some(Ok(())) => {}
            Some(Err(error)) => return Err(error),
            None => return Err(MonitorTransportError::Worker),
        }
        if self.shared.lifecycle.load(Ordering::Acquire) != WORKER_RUNNING
            || self.worker.as_ref().is_none_or(JoinHandle::is_finished)
        {
            return Err(self.shared.failure());
        }
        self.ensure_app_live()
    }

    fn ensure_app_live(&mut self) -> Result<(), MonitorTransportError> {
        match self.session.as_mut() {
            Some(session) => session
                .ensure_app_live(Instant::now() + self.timing.io_slice)
                .map_err(|_| MonitorTransportError::AppServer),
            None => Ok(()),
        }
    }

    pub(super) fn shutdown(
        mut self,
        deadline: Instant,
    ) -> Result<MonitorShutdownComplete, Box<MonitorShutdownFailure>> {
        self.request_stop();
        self.interrupt_worker_io();
        match self.wait_and_join(deadline) {
            Ok(()) => Ok(MonitorShutdownComplete {
                session: self.session.take(),
            }),
            Err(MonitorWaitAndJoinError::Failed(error)) if self.worker.is_some() => {
                Err(Box::new(MonitorShutdownFailure {
                    ownership: MonitorShutdownOwnership::PendingJoin(Box::new(self)),
                    error,
                }))
            }
            Err(MonitorWaitAndJoinError::Failed(error)) => Err(Box::new(MonitorShutdownFailure {
                ownership: MonitorShutdownOwnership::JoinedFailed(Box::new(self.session.take())),
                error,
            })),
            Err(MonitorWaitAndJoinError::Panicked) => Err(Box::new(MonitorShutdownFailure {
                ownership: MonitorShutdownOwnership::JoinedPanicked(Box::new(self.session.take())),
                error: MonitorTransportError::Worker,
            })),
        }
    }

    fn request_stop(&self) {
        let _ = self.shared.lifecycle.compare_exchange(
            WORKER_STARTING,
            WORKER_STOPPING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let _ = self.shared.lifecycle.compare_exchange(
            WORKER_RUNNING,
            WORKER_STOPPING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn interrupt_worker_io(&self) {
        // The worker owns another descriptor for this same socket, so dropping
        // the control duplicate cannot wake a persistent blocking read. The
        // lifecycle must transition first so the resulting transport error is
        // classified as an intentional stop rather than a real worker failure.
        let _ = self.control.shutdown(Shutdown::Both);
    }

    fn wait_and_join(&mut self, deadline: Instant) -> Result<(), MonitorWaitAndJoinError> {
        let failed_before_stop = self.shared.lifecycle.load(Ordering::Acquire) == WORKER_FAILED;
        let prior_failure = failed_before_stop.then(|| self.shared.failure());
        loop {
            let now = Instant::now();
            if now >= deadline {
                // Preserve a concurrently recorded real failure. Forced
                // cancellation may replace only a still-live stopping state;
                // it must never overwrite WORKER_FAILED and later flatten the
                // underlying protocol/worker error into success.
                let _ = self.shared.lifecycle.compare_exchange(
                    WORKER_STOPPING,
                    WORKER_FORCED_STOPPING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                self.interrupt_worker_io();
                return Err(MonitorWaitAndJoinError::Failed(
                    MonitorTransportError::Timeout,
                ));
            }
            let Some(worker) = self.worker.as_ref() else {
                return Err(MonitorWaitAndJoinError::Failed(
                    MonitorTransportError::Worker,
                ));
            };
            if worker.is_finished() {
                break;
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(2)),
            );
        }
        let worker_result = match self.worker.take() {
            Some(worker) => match worker.join() {
                Ok(result) => result,
                Err(_) => {
                    self.shared
                        .lifecycle
                        .store(WORKER_STOPPED, Ordering::Release);
                    return Err(MonitorWaitAndJoinError::Panicked);
                }
            },
            None => {
                return Err(MonitorWaitAndJoinError::Failed(
                    MonitorTransportError::Worker,
                ));
            }
        };
        self.shared
            .lifecycle
            .store(WORKER_STOPPED, Ordering::Release);
        match prior_failure {
            Some(error) => Err(MonitorWaitAndJoinError::Failed(error)),
            None => worker_result.map_err(MonitorWaitAndJoinError::Failed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MonitorWaitAndJoinError {
    Failed(MonitorTransportError),
    Panicked,
}

#[cfg(test)]
impl MonitorWorker {
    fn spawn_connected_with_timing(
        stream: UnixStream,
        protocol: MonitorProtocol,
        initialize: MonitorCommand,
        timing: MonitorTiming,
    ) -> Result<Self, MonitorTransportError> {
        Self::spawn_connected_owned(
            stream,
            protocol,
            initialize,
            timing,
            None::<ConnectedMonitorSession>,
        )
        .map_err(|(error, _)| error)
    }
}

fn finalize_worker_run(
    result: Result<(), WorkerRunError>,
    shared: &MonitorShared,
    startup: &SyncSender<Result<(), MonitorTransportError>>,
) -> Result<(), MonitorTransportError> {
    match result {
        Err(WorkerRunError::Stopped) => {
            shared.lifecycle.store(WORKER_STOPPED, Ordering::Release);
            Ok(())
        }
        Err(WorkerRunError::Failed(error)) => {
            let _ = startup.try_send(Err(error));
            Err(error)
        }
        Ok(()) => {
            let error = MonitorTransportError::Transport;
            let claimed = shared.claim_failure(error);
            finalize_worker_run(Err(claimed), shared, startup)
        }
    }
}

impl fmt::Debug for MonitorWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MonitorWorker(<redacted>)")
    }
}

impl Drop for MonitorWorker {
    fn drop(&mut self) {
        // Drop can request bounded worker exit, but it must never perform an
        // unbounded join or manufacture clean shutdown evidence. Callers that
        // need the proof must consume `shutdown` and its completion token.
        self.request_stop();
    }
}

#[must_use = "monitor shutdown proof returns the exact App Server session"]
pub(super) struct MonitorShutdownComplete {
    session: Option<ConnectedMonitorSession>,
}

impl MonitorShutdownComplete {
    pub(super) fn into_session(self) -> Option<ConnectedMonitorSession> {
        self.session
    }
}

#[must_use = "a timed-out monitor worker retains join ownership"]
pub(super) struct MonitorShutdownFailure {
    ownership: MonitorShutdownOwnership,
    error: MonitorTransportError,
}

enum MonitorShutdownOwnership {
    PendingJoin(Box<MonitorWorker>),
    JoinedFailed(Box<Option<ConnectedMonitorSession>>),
    JoinedPanicked(Box<Option<ConnectedMonitorSession>>),
}

pub(super) enum MonitorShutdownOwner {
    PendingJoin(MonitorWorker),
    JoinedFailed(Option<ConnectedMonitorSession>),
    JoinedPanicked(Option<ConnectedMonitorSession>),
}

impl MonitorShutdownFailure {
    pub(super) const fn error(&self) -> MonitorTransportError {
        self.error
    }

    /// Forces the caller to distinguish a still-live join authority from an
    /// already-joined operation failure carrying the recovered App session.
    #[expect(
        clippy::boxed_local,
        reason = "the shutdown API deliberately returns a boxed linear failure owner"
    )]
    pub(super) fn into_owner(self: Box<Self>) -> MonitorShutdownOwner {
        match self.ownership {
            MonitorShutdownOwnership::PendingJoin(worker) => {
                MonitorShutdownOwner::PendingJoin(*worker)
            }
            MonitorShutdownOwnership::JoinedFailed(session) => {
                MonitorShutdownOwner::JoinedFailed(*session)
            }
            MonitorShutdownOwnership::JoinedPanicked(session) => {
                MonitorShutdownOwner::JoinedPanicked(*session)
            }
        }
    }
}

impl fmt::Debug for MonitorShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonitorShutdownFailure")
            .field("error", &self.error)
            .field(
                "state",
                &match &self.ownership {
                    MonitorShutdownOwnership::PendingJoin(_) => "pending-join",
                    MonitorShutdownOwnership::JoinedFailed(_) => "joined-failed",
                    MonitorShutdownOwnership::JoinedPanicked(_) => "joined-panicked",
                },
            )
            .finish_non_exhaustive()
    }
}

impl fmt::Display for MonitorShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for MonitorShutdownFailure {}

fn run_worker(
    stream: UnixStream,
    mut protocol: MonitorProtocol,
    initialize: MonitorCommand,
    timing: MonitorTiming,
    shared: &MonitorShared,
    startup: &SyncSender<Result<(), MonitorTransportError>>,
) -> Result<(), WorkerRunError> {
    let startup_deadline =
        checked_deadline(timing.startup_timeout).map_err(|error| shared.claim_failure(error))?;
    let stream = DeadlineUnixStream::new(stream, timing.io_slice, Some(startup_deadline));
    let handshake = client_with_config(WEBSOCKET_ENDPOINT, stream, Some(websocket_config()));
    let Some(mut websocket) =
        complete_monitor_client_handshake(handshake, startup_deadline, &shared.lifecycle)
            .map_err(|error| shared.claim_failure(error))?
    else {
        return Err(WorkerRunError::Stopped);
    };
    websocket.get_mut().finish_handshake();

    send_command(&mut websocket, &initialize, startup_deadline)
        .map_err(|error| shared.claim_failure(error))?;
    let mut pending_deadline = Some(startup_deadline);
    let mut next_poll = None;
    let mut ready = false;

    loop {
        if matches!(
            shared.lifecycle.load(Ordering::Acquire),
            WORKER_STOPPING | WORKER_FORCED_STOPPING
        ) {
            return Err(WorkerRunError::Stopped);
        }
        let now = Instant::now();
        if pending_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(shared.claim_failure(MonitorTransportError::Timeout));
        }
        if pending_deadline.is_none() && next_poll.is_some_and(|deadline| now >= deadline) {
            let actions = protocol
                .request_refresh()
                .map_err(map_protocol_error)
                .map_err(|error| shared.claim_failure(error))?;
            sync_authoritative_usage(&protocol, shared)
                .map_err(|error| shared.claim_failure(error))?;
            apply_actions(
                &mut websocket,
                actions,
                timing,
                shared,
                startup,
                &mut ready,
                &mut pending_deadline,
                &mut next_poll,
            )
            .map_err(|error| shared.claim_failure(error))?;
        }

        websocket.get_mut().set_deadline(pending_deadline);
        match websocket.read() {
            Ok(Message::Text(text)) => {
                let actions = protocol
                    .receive(text.as_bytes())
                    .map_err(map_protocol_error)
                    .map_err(|error| shared.claim_failure(error))?;
                sync_authoritative_usage(&protocol, shared)
                    .map_err(|error| shared.claim_failure(error))?;
                apply_actions(
                    &mut websocket,
                    actions,
                    timing,
                    shared,
                    startup,
                    &mut ready,
                    &mut pending_deadline,
                    &mut next_poll,
                )
                .map_err(|error| shared.claim_failure(error))?;
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Ok(Message::Close(_)) => {
                return Err(shared.claim_failure(MonitorTransportError::Transport));
            }
            Ok(Message::Binary(_) | Message::Frame(_)) => {
                return Err(shared.claim_failure(MonitorTransportError::Protocol));
            }
            Err(WebSocketError::Io(error)) if io_error_is_retryable(&error) => {}
            Err(error) => return Err(shared.claim_failure(map_websocket_error(error))),
        }
    }
}

fn sync_authoritative_usage(
    protocol: &MonitorProtocol,
    shared: &MonitorShared,
) -> Result<(), MonitorTransportError> {
    *shared
        .latest_usage
        .lock()
        .map_err(|_| MonitorTransportError::Worker)? = protocol.latest_usage().cloned();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_actions(
    websocket: &mut WebSocket<DeadlineUnixStream>,
    actions: Vec<MonitorAction>,
    timing: MonitorTiming,
    shared: &MonitorShared,
    startup: &SyncSender<Result<(), MonitorTransportError>>,
    ready: &mut bool,
    pending_deadline: &mut Option<Instant>,
    next_poll: &mut Option<Instant>,
) -> Result<(), MonitorTransportError> {
    for action in actions {
        match action {
            MonitorAction::Outbound(command) => {
                let deadline = checked_deadline(timing.request_timeout)?;
                send_command(websocket, &command, deadline)?;
                if matches!(command, MonitorCommand::ReadUsage { .. }) {
                    *pending_deadline = Some(deadline);
                    *next_poll = None;
                }
            }
            MonitorAction::PublishUsage(usage) => {
                if !publish_usage(shared, startup, ready, *usage)? {
                    return Ok(());
                }
                *pending_deadline = None;
                *next_poll = Some(checked_deadline(timing.poll_interval)?);
            }
            MonitorAction::UsageLimitExceeded { thread_id, turn_id } => {
                *shared
                    .usage_limit
                    .lock()
                    .map_err(|_| MonitorTransportError::Worker)? =
                    Some(UsageLimitSignal { thread_id, turn_id });
            }
        }
    }
    Ok(())
}

/// Publishes the first snapshot only if this worker still owns the transition
/// from STARTING to RUNNING. In particular, a concurrent shutdown that has
/// already moved STARTING to STOPPING cannot be overwritten by a late usage
/// response.
fn publish_usage(
    shared: &MonitorShared,
    startup: &SyncSender<Result<(), MonitorTransportError>>,
    ready: &mut bool,
    usage: CodexUsage,
) -> Result<bool, MonitorTransportError> {
    let first = !*ready;
    if first {
        match shared.lifecycle.compare_exchange(
            WORKER_STARTING,
            WORKER_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(WORKER_STOPPING | WORKER_FORCED_STOPPING) => return Ok(false),
            Err(_) => return Err(MonitorTransportError::Worker),
        }
    } else if shared.lifecycle.load(Ordering::Acquire) != WORKER_RUNNING {
        return Ok(false);
    }
    *shared
        .latest_usage
        .lock()
        .map_err(|_| MonitorTransportError::Worker)? = Some(usage);
    if first {
        *ready = true;
        let _ = startup.try_send(Ok(()));
    }
    Ok(true)
}

fn send_command(
    websocket: &mut WebSocket<DeadlineUnixStream>,
    command: &MonitorCommand,
    deadline: Instant,
) -> Result<(), MonitorTransportError> {
    let encoded = command.encode().map_err(map_protocol_error)?;
    if encoded.len() > MAX_OUTBOUND_COMMAND_BYTES {
        return Err(MonitorTransportError::Protocol);
    }
    let text = String::from_utf8(encoded).map_err(|_| MonitorTransportError::Protocol)?;
    websocket.get_mut().set_deadline(Some(deadline));
    websocket
        .send(Message::text(text))
        .map_err(map_websocket_error)
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(READ_BUFFER_BYTES)
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES))
        .accept_unmasked_frames(false)
}

fn checked_deadline(timeout: Duration) -> Result<Instant, MonitorTransportError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(MonitorTransportError::InvalidArgument)
}

fn map_protocol_error(error: MonitorError) -> MonitorTransportError {
    match error {
        MonitorError::InvalidArgument => MonitorTransportError::InvalidArgument,
        MonitorError::InvalidMessage
        | MonitorError::UnexpectedSequence
        | MonitorError::HomeIdentityChanged => MonitorTransportError::Protocol,
        MonitorError::Usage(error) => match error {
            CodexUsageError::Unsupported => MonitorTransportError::Unsupported,
            CodexUsageError::Protocol => MonitorTransportError::Protocol,
            CodexUsageError::Authentication => MonitorTransportError::Authentication,
            CodexUsageError::Timeout => MonitorTransportError::Timeout,
            CodexUsageError::Transport => MonitorTransportError::Transport,
            CodexUsageError::Provider => MonitorTransportError::Provider,
            CodexUsageError::Spawn => MonitorTransportError::AppServer,
        },
    }
}

fn map_handshake_error(
    error: HandshakeError<tungstenite::handshake::client::ClientHandshake<DeadlineUnixStream>>,
) -> MonitorTransportError {
    match error {
        HandshakeError::Failure(WebSocketError::Io(error)) if io_error_is_retryable(&error) => {
            MonitorTransportError::Timeout
        }
        HandshakeError::Failure(_) | HandshakeError::Interrupted(_) => {
            MonitorTransportError::Handshake
        }
    }
}

type MonitorClientHandshake = tungstenite::handshake::client::ClientHandshake<DeadlineUnixStream>;
type MonitorClientHandshakeResult = Result<
    (
        WebSocket<DeadlineUnixStream>,
        tungstenite::handshake::client::Response,
    ),
    HandshakeError<MonitorClientHandshake>,
>;

fn complete_monitor_client_handshake(
    mut result: MonitorClientHandshakeResult,
    deadline: Instant,
    lifecycle: &AtomicU8,
) -> Result<Option<WebSocket<DeadlineUnixStream>>, MonitorTransportError> {
    loop {
        if matches!(
            lifecycle.load(Ordering::Acquire),
            WORKER_STOPPING | WORKER_FORCED_STOPPING
        ) {
            return Ok(None);
        }
        match result {
            Ok((websocket, _response)) => return Ok(Some(websocket)),
            Err(HandshakeError::Failure(error)) => {
                return Err(map_handshake_error(HandshakeError::Failure(error)));
            }
            Err(HandshakeError::Interrupted(handshake)) => {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(MonitorTransportError::Timeout);
                };
                if remaining.is_zero() {
                    return Err(MonitorTransportError::Timeout);
                }
                thread::sleep(remaining.min(Duration::from_millis(1)));
                result = handshake.handshake();
            }
        }
    }
}

fn map_websocket_error(error: WebSocketError) -> MonitorTransportError {
    match error {
        WebSocketError::Io(error) if io_error_is_retryable(&error) => {
            MonitorTransportError::Timeout
        }
        WebSocketError::Io(_) => MonitorTransportError::Transport,
        WebSocketError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
            MonitorTransportError::Transport
        }
        WebSocketError::Capacity(_) | WebSocketError::Protocol(_) | WebSocketError::Utf8(_) => {
            MonitorTransportError::Protocol
        }
        WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed => {
            MonitorTransportError::Transport
        }
        _ => MonitorTransportError::Handshake,
    }
}

fn io_error_is_retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

struct DeadlineUnixStream {
    stream: UnixStream,
    io_slice: Duration,
    deadline: Option<Instant>,
    handshake_bytes_remaining: Option<usize>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl DeadlineUnixStream {
    fn new(stream: UnixStream, io_slice: Duration, deadline: Option<Instant>) -> Self {
        Self {
            stream,
            io_slice,
            deadline,
            handshake_bytes_remaining: Some(MAX_HANDSHAKE_BYTES),
            read_timeout: None,
            write_timeout: None,
        }
    }

    fn finish_handshake(&mut self) {
        self.handshake_bytes_remaining = None;
    }

    fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    fn operation_timeout(&self) -> io::Result<Duration> {
        let timeout = match self.deadline {
            Some(deadline) => deadline
                .checked_duration_since(Instant::now())
                .map(|remaining| remaining.min(self.io_slice))
                .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?,
            None => self.io_slice,
        };
        if timeout.is_zero() {
            Err(io::Error::from(io::ErrorKind::TimedOut))
        } else {
            Ok(timeout)
        }
    }

    fn ensure_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        // Keep the absolute deadline in user space and avoid issuing an
        // identical SO_RCVTIMEO update for every 4 KiB handshake chunk. Darwin
        // can reject a later redundant update on a live Unix socket with
        // EINVAL; caching the requested value is both cheaper and portable.
        if self.read_timeout != Some(timeout) {
            self.stream.set_read_timeout(Some(timeout))?;
            self.read_timeout = Some(timeout);
        }
        Ok(())
    }

    fn ensure_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        // Match the read side so a fragmented write cannot turn repeated
        // timeout setup into a transport failure on Darwin.
        if self.write_timeout != Some(timeout) {
            self.stream.set_write_timeout(Some(timeout))?;
            self.write_timeout = Some(timeout);
        }
        Ok(())
    }

    fn normalize_handshake_slice_error(&self, error: io::Error) -> io::Error {
        if self.handshake_bytes_remaining.is_some()
            && io_error_is_retryable(&error)
            && self
                .deadline
                .is_some_and(|deadline| Instant::now() < deadline)
        {
            io::Error::from(io::ErrorKind::WouldBlock)
        } else {
            error
        }
    }
}

impl Read for DeadlineUnixStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let readable = match self.handshake_bytes_remaining {
            Some(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Codex monitor WebSocket handshake exceeded its bound",
                ));
            }
            Some(remaining) => buffer.len().min(remaining),
            None => buffer.len(),
        };
        let timeout = self.operation_timeout()?;
        self.ensure_read_timeout(timeout)?;
        let read = self
            .stream
            .read(&mut buffer[..readable])
            .map_err(|error| self.normalize_handshake_slice_error(error))?;
        if let Some(remaining) = self.handshake_bytes_remaining.as_mut() {
            *remaining = remaining.saturating_sub(read);
        }
        Ok(read)
    }
}

impl Write for DeadlineUnixStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let timeout = self.operation_timeout()?;
        self.ensure_write_timeout(timeout)?;
        self.stream
            .write(buffer)
            .map_err(|error| self.normalize_handshake_slice_error(error))
    }

    fn flush(&mut self) -> io::Result<()> {
        let timeout = self.operation_timeout()?;
        self.ensure_write_timeout(timeout)?;
        self.stream
            .flush()
            .map_err(|error| self.normalize_handshake_slice_error(error))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use serde_json::{Value, json};
    use tungstenite::{accept_with_config, protocol::WebSocket};

    use super::*;

    const THREAD_ID: &str = "019c6e27-e55b-73d1-87d8-4e01f1f75043";
    const TURN_ID: &str = "019c7714-3b77-74d1-9866-e1f484aae2ab";

    #[test]
    fn usage_limit_signal_debug_redacts_provider_identifiers() {
        let signal = UsageLimitSignal {
            thread_id: THREAD_ID.to_owned(),
            turn_id: TURN_ID.to_owned(),
        };

        let debug = format!("{signal:?}");
        assert_eq!(debug, "UsageLimitSignal(<redacted>)");
        assert!(!debug.contains(THREAD_ID));
        assert!(!debug.contains(TURN_ID));
    }

    struct TraceCapture {
        messages: Mutex<Vec<String>>,
    }

    impl log::Log for TraceCapture {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            if let Ok(mut messages) = self.messages.lock() {
                messages.push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    static TRACE_CAPTURE: TraceCapture = TraceCapture {
        messages: Mutex::new(Vec::new()),
    };

    fn test_timing() -> MonitorTiming {
        MonitorTiming {
            io_slice: Duration::from_millis(20),
            startup_timeout: Duration::from_millis(750),
            request_timeout: Duration::from_millis(500),
            poll_interval: Duration::from_millis(50),
        }
    }

    fn shutdown_deadline() -> Result<Instant, MonitorTransportError> {
        checked_deadline(Duration::from_secs(1))
    }

    fn connected_monitor(stream: UnixStream, home: &Path) -> Result<MonitorWorker, Box<dyn Error>> {
        let (protocol, initialize) = MonitorProtocol::start(home, THREAD_ID)?;
        Ok(MonitorWorker::spawn_connected_with_timing(
            stream,
            protocol,
            initialize,
            test_timing(),
        )?)
    }

    #[test]
    fn startup_readiness_preserves_existing_and_app_server_error_categories() {
        let liveness_check_called = Cell::new(false);
        assert_eq!(
            finalize_startup_readiness(Err(MonitorTransportError::Protocol), || {
                liveness_check_called.set(true);
                Err(MonitorTransportError::AppServer)
            }),
            Err(MonitorTransportError::Protocol)
        );
        assert!(
            !liveness_check_called.get(),
            "an existing startup error must short-circuit the App liveness check"
        );

        for (app_liveness, expected) in [
            (Ok(()), Ok(())),
            (
                Err(MonitorTransportError::AppServer),
                Err(MonitorTransportError::AppServer),
            ),
        ] {
            assert_eq!(
                finalize_startup_readiness(Ok(()), || app_liveness),
                expected
            );
        }
    }

    #[test]
    fn late_first_usage_cannot_revive_a_stopping_worker() -> Result<(), Box<dyn Error>> {
        let shared = MonitorShared::new();
        shared.lifecycle.store(WORKER_STOPPING, Ordering::Release);
        let (startup_sender, startup) = mpsc::sync_channel(1);
        let mut ready = false;
        let usage = CodexUsage {
            rate_limits: None,
            rate_limits_by_limit_id: std::collections::BTreeMap::new(),
            reset_credits: None,
        };

        assert!(!publish_usage(&shared, &startup_sender, &mut ready, usage)?);
        assert!(!ready);
        assert_eq!(shared.lifecycle.load(Ordering::Acquire), WORKER_STOPPING);
        {
            let latest = shared
                .latest_usage
                .lock()
                .map_err(|_| "latest usage mutex poisoned")?;
            assert!(latest.is_none());
        }
        assert!(matches!(startup.try_recv(), Err(mpsc::TryRecvError::Empty)));
        Ok(())
    }

    #[test]
    fn claimed_transport_failure_cannot_be_reclassified_by_a_later_shutdown()
    -> Result<(), Box<dyn Error>> {
        let shared = Arc::new(MonitorShared::new());
        shared.lifecycle.store(WORKER_RUNNING, Ordering::Release);
        let worker_shared = Arc::clone(&shared);
        let (startup_sender, _startup) = mpsc::sync_channel(1);
        let (returned_sender, returned_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            let result = Err(worker_shared.claim_failure(MonitorTransportError::Transport));
            returned_sender
                .send(())
                .map_err(|_| "failure-return barrier receiver disappeared")?;
            release_receiver
                .recv()
                .map_err(|_| "failure-finalize barrier sender disappeared")?;
            Ok::<_, &'static str>(finalize_worker_run(result, &worker_shared, &startup_sender))
        });

        returned_receiver.recv()?;
        assert!(matches!(
            shared.claim_failure(MonitorTransportError::Protocol),
            WorkerRunError::Failed(MonitorTransportError::Transport)
        ));
        assert_eq!(
            shared.lifecycle.compare_exchange(
                WORKER_RUNNING,
                WORKER_STOPPING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Err(WORKER_FAILED)
        );
        release_sender.send(())?;
        let outcome = worker
            .join()
            .map_err(|_| "failure-finalize worker panicked")??;
        assert_eq!(outcome, Err(MonitorTransportError::Transport));
        assert_eq!(shared.lifecycle.load(Ordering::Acquire), WORKER_FAILED);
        assert_eq!(shared.failure(), MonitorTransportError::Transport);
        Ok(())
    }

    #[test]
    fn protocol_mapping_preserves_redacted_usage_failure_categories() {
        assert_eq!(
            [
                CodexUsageError::Unsupported,
                CodexUsageError::Protocol,
                CodexUsageError::Authentication,
                CodexUsageError::Timeout,
                CodexUsageError::Transport,
                CodexUsageError::Provider,
                CodexUsageError::Spawn,
            ]
            .map(|error| map_protocol_error(MonitorError::Usage(error))),
            [
                MonitorTransportError::Unsupported,
                MonitorTransportError::Protocol,
                MonitorTransportError::Authentication,
                MonitorTransportError::Timeout,
                MonitorTransportError::Transport,
                MonitorTransportError::Provider,
                MonitorTransportError::AppServer,
            ]
        );
        assert_eq!(
            map_protocol_error(MonitorError::InvalidArgument),
            MonitorTransportError::InvalidArgument
        );
        assert_eq!(
            [
                MonitorError::InvalidMessage,
                MonitorError::UnexpectedSequence,
                MonitorError::HomeIdentityChanged,
            ]
            .map(map_protocol_error),
            [MonitorTransportError::Protocol; 3]
        );
    }

    #[test]
    fn websocket_handshake_accepts_exact_bound_and_rejects_bound_plus_one()
    -> Result<(), Box<dyn Error>> {
        let (exact_client, exact_server) = UnixStream::pair()?;
        let exact_server = spawn_raw_handshake_server(exact_server, MAX_HANDSHAKE_BYTES);
        let exact_deadline = checked_deadline(Duration::from_secs(1))?;
        let exact_stream = DeadlineUnixStream::new(
            exact_client,
            Duration::from_millis(20),
            Some(exact_deadline),
        );
        let lifecycle = AtomicU8::new(WORKER_STARTING);
        let mut exact_websocket = complete_monitor_client_handshake(
            client_with_config(WEBSOCKET_ENDPOINT, exact_stream, Some(websocket_config())),
            exact_deadline,
            &lifecycle,
        )?
        .ok_or("an exact-bound handshake was misclassified as stopped")?;
        exact_websocket.get_mut().finish_handshake();
        drop(exact_websocket);
        join_server(exact_server)?;

        let (over_client, over_server) = UnixStream::pair()?;
        let over_server = spawn_raw_handshake_server(over_server, MAX_HANDSHAKE_BYTES + 1);
        let over_deadline = checked_deadline(Duration::from_secs(1))?;
        let over_stream =
            DeadlineUnixStream::new(over_client, Duration::from_millis(20), Some(over_deadline));
        let lifecycle = AtomicU8::new(WORKER_STARTING);
        let error = complete_monitor_client_handshake(
            client_with_config(WEBSOCKET_ENDPOINT, over_stream, Some(websocket_config())),
            over_deadline,
            &lifecycle,
        )
        .err()
        .ok_or("an oversized handshake unexpectedly succeeded")?;
        assert_eq!(error, MonitorTransportError::Handshake);
        join_server(over_server)?;
        Ok(())
    }

    #[test]
    fn websocket_handshake_resumes_io_slices_until_its_absolute_deadline()
    -> Result<(), Box<dyn Error>> {
        let (client, server) = UnixStream::pair()?;
        let server = thread::spawn(move || -> ServerResult {
            thread::sleep(Duration::from_millis(80));
            server
                .set_read_timeout(Some(Duration::from_secs(1)))
                .map_err(|_| "delayed server read timeout setup failed".to_owned())?;
            server
                .set_write_timeout(Some(Duration::from_secs(1)))
                .map_err(|_| "delayed server write timeout setup failed".to_owned())?;
            let websocket = accept_with_config(server, Some(websocket_config()))
                .map_err(|_| "delayed server handshake failed".to_owned())?;
            drop(websocket);
            Ok(())
        });
        let deadline = checked_deadline(Duration::from_secs(1))?;
        let stream = DeadlineUnixStream::new(client, Duration::from_millis(20), Some(deadline));
        let interrupted = client_with_config(WEBSOCKET_ENDPOINT, stream, Some(websocket_config()));
        assert!(matches!(&interrupted, Err(HandshakeError::Interrupted(_))));
        let lifecycle = AtomicU8::new(WORKER_STARTING);
        let mut websocket = complete_monitor_client_handshake(interrupted, deadline, &lifecycle)?
            .ok_or("an active delayed handshake was misclassified as stopped")?;
        websocket.get_mut().finish_handshake();
        drop(websocket);
        join_server(server)?;

        let (client, server) = UnixStream::pair()?;
        let holder = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            drop(server);
        });
        let deadline = checked_deadline(Duration::from_millis(40))?;
        let stream = DeadlineUnixStream::new(client, Duration::from_millis(10), Some(deadline));
        let interrupted = client_with_config(WEBSOCKET_ENDPOINT, stream, Some(websocket_config()));
        assert!(matches!(&interrupted, Err(HandshakeError::Interrupted(_))));
        let lifecycle = AtomicU8::new(WORKER_STARTING);
        assert!(matches!(
            complete_monitor_client_handshake(interrupted, deadline, &lifecycle),
            Err(MonitorTransportError::Timeout)
        ));
        holder.join().map_err(|_| "handshake holder panicked")?;
        Ok(())
    }

    #[test]
    fn dependency_trace_logging_cannot_render_raw_websocket_payloads() -> Result<(), Box<dyn Error>>
    {
        const SENTINEL: &str = "calcifer-fake-provider-secret-must-not-be-logged";

        assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off);
        log::set_logger(&TRACE_CAPTURE).map_err(|_| "a test logger was already installed")?;
        log::set_max_level(log::LevelFilter::Trace);
        TRACE_CAPTURE
            .messages
            .lock()
            .map_err(|_| "trace capture mutex poisoned")?
            .clear();

        let (client, server) = UnixStream::pair()?;
        let server = spawn_server(server, |websocket| {
            websocket
                .send(Message::text(SENTINEL))
                .map_err(|_| "trace sentinel send failed".to_owned())
        });
        let deadline = checked_deadline(Duration::from_secs(1))?;
        let stream = DeadlineUnixStream::new(client, Duration::from_millis(20), Some(deadline));
        let (mut websocket, _) =
            client_with_config(WEBSOCKET_ENDPOINT, stream, Some(websocket_config()))
                .map_err(map_handshake_error)?;
        websocket.get_mut().finish_handshake();
        assert_eq!(websocket.read()?, Message::text(SENTINEL));
        drop(websocket);
        join_server(server)?;

        let messages = TRACE_CAPTURE
            .messages
            .lock()
            .map_err(|_| "trace capture mutex poisoned")?;
        assert!(
            messages.iter().all(|message| !message.contains(SENTINEL)),
            "a dependency logger rendered a raw provider payload"
        );
        Ok(())
    }

    #[test]
    fn real_websocket_runs_exact_handshake_and_initial_authoritative_read()
    -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        client.set_nonblocking(true)?;
        let server_home = home.path().to_path_buf();
        let server = spawn_server(server, move |websocket| {
            assert_eq!(read_json(websocket)?, initialize_request());
            send_json(websocket, initialize_response(&server_home))?;
            assert_eq!(read_json(websocket)?, json!({ "method": "initialized" }));
            assert_eq!(read_json(websocket)?, usage_read(1));
            send_json(websocket, usage_response(1, 73))?;
            wait_for_disconnect(websocket)
        });

        let mut monitor = connected_monitor(client, home.path())?;
        monitor.wait_until_ready()?;
        let usage = monitor.latest_usage().ok_or("missing live usage")?;
        assert_eq!(
            usage
                .rate_limits
                .and_then(|limits| limits.primary)
                .map(|window| window.remaining_percent),
            Some(27)
        );
        monitor.ensure_live()?;
        let _ = monitor.shutdown(shutdown_deadline()?)?;
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn ping_is_ponged_with_exact_payload_and_monitor_remains_live() -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let server = spawn_server(server, move |websocket| {
            assert_eq!(read_json(websocket)?, initialize_request());
            send_json(websocket, initialize_response(&server_home))?;
            assert_eq!(read_json(websocket)?, json!({ "method": "initialized" }));
            assert_eq!(read_json(websocket)?, usage_read(1));

            let ping_payload = b"calcifer-monitor-ping";
            websocket
                .send(Message::Ping(ping_payload.to_vec().into()))
                .map_err(|_| "monitor ping send failed".to_owned())?;
            match websocket
                .read()
                .map_err(|_| "monitor connection ended before Pong".to_owned())?
            {
                Message::Pong(actual) if actual.as_ref() == ping_payload => {}
                _ => return Err("monitor did not return the exact Pong".to_owned()),
            }

            send_json(websocket, usage_response(1, 73))?;
            wait_for_disconnect(websocket)
        });

        let mut monitor = connected_monitor(client, home.path())?;
        monitor.wait_until_ready()?;
        let usage = monitor
            .latest_usage()
            .ok_or("missing live usage after Ping")?;
        assert_eq!(
            usage
                .rate_limits
                .and_then(|limits| limits.primary)
                .map(|window| window.remaining_percent),
            Some(27)
        );
        monitor.ensure_live()?;
        let _ = monitor.shutdown(shutdown_deadline()?)?;
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn nonblocking_startup_poll_transitions_from_none_to_sticky_success()
    -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let (request_seen_sender, request_seen) = mpsc::sync_channel(1);
        let (release_sender, release) = mpsc::sync_channel(1);
        let server = spawn_server(server, move |websocket| {
            assert_eq!(read_json(websocket)?, initialize_request());
            send_json(websocket, initialize_response(&server_home))?;
            assert_eq!(read_json(websocket)?, json!({ "method": "initialized" }));
            assert_eq!(read_json(websocket)?, usage_read(1));
            request_seen_sender
                .send(())
                .map_err(|_| "startup request observation closed".to_owned())?;
            release
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| "startup response release timed out".to_owned())?;
            send_json(websocket, usage_response(1, 73))?;
            wait_for_disconnect(websocket)
        });

        let mut monitor = connected_monitor(client, home.path())?;
        request_seen.recv_timeout(Duration::from_secs(1))?;
        assert_eq!(monitor.poll_ready(), Ok(None));
        release_sender.send(())?;
        let deadline = checked_deadline(Duration::from_secs(1))?;
        loop {
            match monitor.poll_ready()? {
                Some(()) => break,
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                None => return Err("nonblocking startup readiness did not arrive".into()),
            }
        }
        assert_eq!(monitor.poll_ready(), Ok(Some(())));
        let _ = monitor.shutdown(shutdown_deadline()?)?;
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn nonblocking_startup_failure_is_fatal_and_sticky() -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let server = spawn_server(server, move |websocket| {
            let _ = read_json(websocket)?;
            send_json(websocket, initialize_response(&server_home))?;
            let _ = read_json(websocket)?;
            let _ = read_json(websocket)?;
            send_json(
                websocket,
                json!({
                    "id": { "invalid": true },
                    "method": "item/commandExecution/requestApproval",
                    "params": { "command": "must-not-be-approved" }
                }),
            )?;
            wait_for_disconnect(websocket)
        });

        let mut monitor = connected_monitor(client, home.path())?;
        let deadline = checked_deadline(Duration::from_secs(1))?;
        let failure = loop {
            match monitor.poll_ready() {
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                Ok(None) => return Err("startup failure was not observed".into()),
                Ok(Some(())) => return Err("failed startup was reported ready".into()),
                Err(error) => break error,
            }
        };
        assert_eq!(failure, MonitorTransportError::Protocol);
        assert_eq!(monitor.poll_ready(), Err(MonitorTransportError::Protocol));
        let _ = monitor.shutdown(shutdown_deadline()?);
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn cached_poll_success_is_revoked_after_worker_transport_loss() -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let (release_sender, release) = mpsc::sync_channel(1);
        let server = spawn_server(server, move |websocket| {
            let _ = read_json(websocket)?;
            send_json(websocket, initialize_response(&server_home))?;
            let _ = read_json(websocket)?;
            let _ = read_json(websocket)?;
            send_json(websocket, usage_response(1, 20))?;
            release
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| "disconnect release timed out".to_owned())
        });

        let mut monitor = connected_monitor(client, home.path())?;
        let deadline = checked_deadline(Duration::from_secs(1))?;
        while monitor.poll_ready()? != Some(()) {
            if Instant::now() >= deadline {
                return Err("initial poll readiness did not arrive".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        release_sender.send(())?;
        join_server(server)?;
        let deadline = checked_deadline(Duration::from_secs(1))?;
        let failure = loop {
            match monitor.poll_ready() {
                Ok(Some(())) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(Some(())) => return Err("cached readiness survived transport loss".into()),
                Ok(None) => return Err("cached readiness regressed to pending".into()),
                Err(error) => break error,
            }
        };
        assert_eq!(failure, MonitorTransportError::Transport);
        assert_eq!(monitor.poll_ready(), Err(MonitorTransportError::Transport));
        let _ = monitor.shutdown(shutdown_deadline()?);
        Ok(())
    }

    #[test]
    fn polling_refreshes_without_notifications_and_keeps_one_latest_snapshot()
    -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let (poll_seen_sender, poll_seen) = mpsc::sync_channel(1);
        let (release_sender, release) = mpsc::sync_channel(1);
        let server = spawn_server(server, move |websocket| {
            let _ = read_json(websocket)?;
            send_json(websocket, initialize_response(&server_home))?;
            let _ = read_json(websocket)?;
            assert_eq!(read_json(websocket)?, usage_read(1));
            send_json(websocket, usage_response(1, 10))?;
            assert_eq!(read_json(websocket)?, usage_read(2));
            poll_seen_sender
                .send(())
                .map_err(|_| "poll observation channel closed".to_owned())?;
            release
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| "poll release timed out".to_owned())?;
            send_json(websocket, usage_response(2, 80))?;
            wait_for_disconnect(websocket)
        });

        let mut monitor = connected_monitor(client, home.path())?;
        monitor.wait_until_ready()?;
        poll_seen.recv_timeout(Duration::from_secs(1))?;
        assert!(
            monitor.latest_usage().is_none(),
            "an in-flight poll must invalidate the older live snapshot"
        );
        release_sender.send(())?;
        let deadline = checked_deadline(Duration::from_secs(1))?;
        loop {
            let used = monitor
                .latest_usage()
                .and_then(|usage| usage.rate_limits)
                .and_then(|limits| limits.primary)
                .map(|window| window.used_percent);
            if used == Some(80) {
                break;
            }
            if Instant::now() >= deadline {
                return Err("timer-driven usage refresh did not arrive".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = monitor.shutdown(shutdown_deadline()?)?;
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn provider_request_emits_no_response_and_later_usage_poll_succeeds()
    -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let server = spawn_server(server, move |websocket| {
            assert_eq!(read_json(websocket)?, initialize_request());
            send_json(websocket, initialize_response(&server_home))?;
            assert_eq!(read_json(websocket)?, json!({ "method": "initialized" }));
            assert_eq!(read_json(websocket)?, usage_read(1));
            send_json(
                websocket,
                json!({
                    "id": "approval",
                    "method": "item/commandExecution/requestApproval",
                    "params": { "command": "provider secret" }
                }),
            )?;
            send_json(websocket, usage_response(1, 10))?;
            assert_eq!(
                read_json(websocket)?,
                usage_read(2),
                "the observe-only monitor emitted a provider response before its next usage poll"
            );
            send_json(websocket, usage_response(2, 80))?;
            wait_for_disconnect(websocket)
        });

        let mut monitor = connected_monitor(client, home.path())?;
        monitor.wait_until_ready()?;
        let deadline = checked_deadline(Duration::from_secs(1))?;
        loop {
            let used = monitor
                .latest_usage()
                .and_then(|usage| usage.rate_limits)
                .and_then(|limits| limits.primary)
                .map(|window| window.used_percent);
            if used == Some(80) {
                break;
            }
            if Instant::now() >= deadline {
                return Err("usage polling did not survive the provider request".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        monitor.ensure_live()?;
        let _ = monitor.shutdown(shutdown_deadline()?)?;
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn initial_usage_rpc_categories_remain_sticky_through_worker_shutdown()
    -> Result<(), Box<dyn Error>> {
        for (code, message, expected) in [
            (
                -32601,
                "raw unsupported provider detail",
                MonitorTransportError::Unsupported,
            ),
            (
                -32600,
                "raw authentication credential detail",
                MonitorTransportError::Authentication,
            ),
            (
                -32000,
                "raw backend provider detail",
                MonitorTransportError::Provider,
            ),
        ] {
            let home = TestDirectory::new()?;
            let (client, server) = UnixStream::pair()?;
            let server_home = home.path().to_path_buf();
            let server = spawn_server(server, move |websocket| {
                assert_eq!(read_json(websocket)?, initialize_request());
                send_json(websocket, initialize_response(&server_home))?;
                assert_eq!(read_json(websocket)?, json!({ "method": "initialized" }));
                assert_eq!(read_json(websocket)?, usage_read(1));
                send_json(
                    websocket,
                    json!({ "id": 1, "error": { "code": code, "message": message } }),
                )?;
                wait_for_disconnect(websocket)
            });

            let mut monitor = connected_monitor(client, home.path())?;
            assert_eq!(monitor.wait_until_ready(), Err(expected));
            assert!(monitor.latest_usage().is_none());
            let failure = monitor
                .shutdown(shutdown_deadline()?)
                .err()
                .ok_or("failed monitor shutdown unexpectedly succeeded")?;
            assert_eq!(failure.error(), expected);
            for rendered in [format!("{failure}"), format!("{failure:?}")] {
                assert!(!rendered.contains("raw"));
                assert!(!rendered.contains("credential"));
                assert!(!rendered.contains("backend"));
            }
            join_server(server)?;
        }
        Ok(())
    }

    #[test]
    fn request_timeout_is_absolute_and_stops_initialization() -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server = spawn_server(server, move |websocket| {
            let _ = read_json(websocket)?;
            thread::sleep(Duration::from_secs(1));
            Ok(())
        });

        let mut monitor = connected_monitor(client, home.path())?;
        assert_eq!(
            monitor.wait_until_ready(),
            Err(MonitorTransportError::Timeout)
        );
        assert!(monitor.latest_usage().is_none());
        let _ = monitor.shutdown(shutdown_deadline()?);
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn oversized_websocket_message_fails_before_json_retention() -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server = spawn_server(server, move |websocket| {
            let _ = read_json(websocket)?;
            // The bounded client is allowed to close as soon as the oversized
            // frame header is observed, before the fake server finishes the
            // write. Either a completed write or BrokenPipe proves that the
            // oversized frame was attempted.
            let _ = websocket.send(Message::text("x".repeat(MAX_MESSAGE_BYTES + 1)));
            Ok(())
        });

        let mut monitor = connected_monitor(client, home.path())?;
        assert_eq!(
            monitor.wait_until_ready(),
            Err(MonitorTransportError::Protocol)
        );
        assert!(monitor.latest_usage().is_none());
        let _ = monitor.shutdown(shutdown_deadline()?);
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn post_ready_disconnect_revokes_liveness_and_stale_usage() -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let (release_sender, release) = mpsc::sync_channel(1);
        let server = spawn_server(server, move |websocket| {
            let _ = read_json(websocket)?;
            send_json(websocket, initialize_response(&server_home))?;
            let _ = read_json(websocket)?;
            let _ = read_json(websocket)?;
            send_json(websocket, usage_response(1, 20))?;
            release
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| "disconnect release timed out".to_owned())
        });

        let mut monitor = connected_monitor(client, home.path())?;
        monitor.wait_until_ready()?;
        assert!(monitor.latest_usage().is_some());
        release_sender.send(())?;
        join_server(server)?;
        let deadline = checked_deadline(Duration::from_secs(1))?;
        while monitor.ensure_live().is_ok() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(monitor.ensure_live(), Err(MonitorTransportError::Transport));
        assert!(monitor.latest_usage().is_none());
        let failure = monitor
            .shutdown(shutdown_deadline()?)
            .err()
            .ok_or("disconnected monitor shutdown unexpectedly succeeded")?;
        assert_eq!(failure.error(), MonitorTransportError::Transport);
        Ok(())
    }

    #[test]
    fn shutdown_timeout_returns_join_ownership_for_a_bounded_retry() -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let server = spawn_server(server, move |websocket| {
            let _ = read_json(websocket)?;
            send_json(websocket, initialize_response(&server_home))?;
            let _ = read_json(websocket)?;
            let _ = read_json(websocket)?;
            send_json(websocket, usage_response(1, 20))?;
            wait_for_disconnect(websocket)
        });

        let mut monitor = connected_monitor(client, home.path())?;
        monitor.wait_until_ready()?;
        let failure = monitor
            .shutdown(Instant::now())
            .err()
            .ok_or("an expired shutdown deadline unexpectedly joined the worker")?;
        assert_eq!(failure.error(), MonitorTransportError::Timeout);
        let retained = match failure.into_owner() {
            MonitorShutdownOwner::PendingJoin(worker) => worker,
            MonitorShutdownOwner::JoinedFailed(_) | MonitorShutdownOwner::JoinedPanicked(_) => {
                return Err("shutdown timeout lost worker join ownership".into());
            }
        };
        let _ = retained.shutdown(shutdown_deadline()?)?;
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn shutdown_interrupts_an_idle_worker_before_the_deadline() -> Result<(), Box<dyn Error>> {
        let home = TestDirectory::new()?;
        let (client, server) = UnixStream::pair()?;
        let server_home = home.path().to_path_buf();
        let server = spawn_server(server, move |websocket| {
            let _ = read_json(websocket)?;
            send_json(websocket, initialize_response(&server_home))?;
            let _ = read_json(websocket)?;
            let _ = read_json(websocket)?;
            send_json(websocket, usage_response(1, 20))?;
            wait_for_disconnect(websocket)
        });
        let (protocol, initialize) = MonitorProtocol::start(home.path(), THREAD_ID)?;
        let timing = MonitorTiming {
            // Keep the worker's persistent read blocked beyond the shutdown
            // deadline. Shutdown must wake that read through its control
            // duplicate rather than depend on the ordinary I/O slice.
            io_slice: Duration::from_secs(5),
            ..test_timing()
        };
        let mut monitor =
            MonitorWorker::spawn_connected_with_timing(client, protocol, initialize, timing)?;
        monitor.wait_until_ready()?;
        thread::sleep(Duration::from_millis(20));

        let deadline = checked_deadline(Duration::from_millis(200))?;
        let complete = match monitor.shutdown(deadline) {
            Ok(complete) => complete,
            Err(failure) => {
                let error = failure.error();
                match failure.into_owner() {
                    MonitorShutdownOwner::PendingJoin(worker) => {
                        let _ = worker.shutdown(shutdown_deadline()?)?;
                    }
                    MonitorShutdownOwner::JoinedFailed(_)
                    | MonitorShutdownOwner::JoinedPanicked(_) => {}
                }
                join_server(server)?;
                return Err(format!(
                    "idle monitor worker was not interrupted before its shutdown deadline: {error}"
                )
                .into());
            }
        };

        assert!(
            complete.into_session().is_none(),
            "test-only monitor shutdown changed its exact session ownership"
        );
        join_server(server)?;
        Ok(())
    }

    #[test]
    fn shutdown_preserves_panicked_join_as_distinct_terminal_owner() -> Result<(), Box<dyn Error>> {
        let (control, _peer) = UnixStream::pair()?;
        let (_startup_sender, startup) = mpsc::sync_channel(1);
        let shared = Arc::new(MonitorShared::new());
        shared.lifecycle.store(WORKER_RUNNING, Ordering::Release);
        let worker = thread::spawn(|| -> Result<(), MonitorTransportError> {
            panic!("injected monitor worker panic")
        });
        let monitor = MonitorWorker {
            control,
            shared,
            startup,
            startup_result: Some(Ok(())),
            worker: Some(worker),
            timing: MonitorTiming::DEFAULT,
            session: None,
        };

        let failure = monitor
            .shutdown(shutdown_deadline()?)
            .err()
            .ok_or("panicked monitor worker unexpectedly joined cleanly")?;
        assert_eq!(failure.error(), MonitorTransportError::Worker);
        assert!(matches!(
            failure.into_owner(),
            MonitorShutdownOwner::JoinedPanicked(None)
        ));
        Ok(())
    }

    type ServerResult = Result<(), String>;

    fn spawn_server<F>(stream: UnixStream, run: F) -> JoinHandle<ServerResult>
    where
        F: FnOnce(&mut WebSocket<UnixStream>) -> ServerResult + Send + 'static,
    {
        thread::spawn(move || {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|_| "server read timeout setup failed".to_owned())?;
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .map_err(|_| "server write timeout setup failed".to_owned())?;
            let server_config = WebSocketConfig::default()
                .max_message_size(Some(MAX_MESSAGE_BYTES * 2))
                .max_frame_size(Some(MAX_MESSAGE_BYTES * 2));
            let mut websocket = accept_with_config(stream, Some(server_config))
                .map_err(|_| "server handshake failed".to_owned())?;
            run(&mut websocket)
        })
    }

    fn spawn_raw_handshake_server(
        mut stream: UnixStream,
        response_bytes: usize,
    ) -> JoinHandle<ServerResult> {
        thread::spawn(move || {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|_| "raw server read timeout setup failed".to_owned())?;
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .map_err(|_| "raw server write timeout setup failed".to_owned())?;
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                if request.len() >= MAX_HANDSHAKE_BYTES {
                    return Err("raw client handshake exceeded its test bound".to_owned());
                }
                let read = stream
                    .read(&mut chunk)
                    .map_err(|_| "raw server request read failed".to_owned())?;
                if read == 0 {
                    return Err("raw client handshake ended early".to_owned());
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let request = String::from_utf8(request)
                .map_err(|_| "raw client handshake was not UTF-8".to_owned())?;
            let key = request
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
                .map(|(_, value)| value.trim())
                .ok_or_else(|| "raw client handshake omitted its key".to_owned())?;
            let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
            let prefix = format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nX-Padding: "
            );
            let suffix = "\r\n\r\n";
            let fixed = prefix
                .len()
                .checked_add(suffix.len())
                .ok_or_else(|| "raw server response length overflowed".to_owned())?;
            let padding = response_bytes
                .checked_sub(fixed)
                .ok_or_else(|| "raw server response bound was too small".to_owned())?;
            let mut response = Vec::with_capacity(response_bytes);
            response.extend_from_slice(prefix.as_bytes());
            response.resize(prefix.len() + padding, b'x');
            response.extend_from_slice(suffix.as_bytes());
            if response.len() != response_bytes {
                return Err("raw server response length mismatched".to_owned());
            }
            // The bounded client may close as soon as it consumes exactly its
            // 16 KiB allowance. A resulting BrokenPipe on the +1 case is the
            // expected peer-side enforcement, not a fake-server failure.
            let _ = stream.write_all(&response);
            Ok(())
        })
    }

    fn join_server(worker: JoinHandle<ServerResult>) -> Result<(), Box<dyn Error>> {
        match worker.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err("fake App Server panicked".into()),
        }
    }

    fn read_json(websocket: &mut WebSocket<UnixStream>) -> Result<Value, String> {
        loop {
            match websocket.read() {
                Ok(Message::Text(text)) => {
                    return serde_json::from_slice(text.as_bytes())
                        .map_err(|_| "server received invalid JSON".to_owned());
                }
                Ok(Message::Ping(_) | Message::Pong(_)) => {}
                Ok(_) => return Err("server received non-text protocol data".to_owned()),
                Err(_) => return Err("server connection ended".to_owned()),
            }
        }
    }

    fn send_json(websocket: &mut WebSocket<UnixStream>, value: Value) -> ServerResult {
        let encoded =
            serde_json::to_string(&value).map_err(|_| "server JSON encoding failed".to_owned())?;
        websocket
            .send(Message::text(encoded))
            .map_err(|_| "server send failed".to_owned())
    }

    fn wait_for_disconnect(websocket: &mut WebSocket<UnixStream>) -> ServerResult {
        loop {
            match websocket.read() {
                Ok(_) => {}
                Err(_) => return Ok(()),
            }
        }
    }

    fn initialize_request() -> Value {
        json!({
            "id": 0,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "calcifer",
                    "title": "Calcifer",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": { "experimentalApi": false }
            }
        })
    }

    fn initialize_response(home: &Path) -> Value {
        json!({
            "id": 0,
            "result": {
                "userAgent": "calcifer/0.144.4",
                "codexHome": home,
                "platformFamily": "unix",
                "platformOs": std::env::consts::OS
            }
        })
    }

    fn usage_read(id: u64) -> Value {
        json!({ "id": id, "method": "account/rateLimits/read" })
    }

    fn usage_response(id: u64, used_percent: u32) -> Value {
        json!({
            "id": id,
            "result": {
                "rateLimits": {
                    "limitId": "codex",
                    "primary": { "usedPercent": used_percent }
                }
            }
        })
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> io::Result<Self> {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let raw = std::env::temp_dir().join(format!(
                "calcifer-monitor-transport-test-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, AtomicOrdering::Relaxed)
            ));
            fs::create_dir(&raw)?;
            fs::set_permissions(&raw, fs::Permissions::from_mode(0o700))?;
            Ok(Self {
                path: fs::canonicalize(raw)?,
            })
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
