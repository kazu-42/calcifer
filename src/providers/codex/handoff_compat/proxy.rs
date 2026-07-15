//! Bounded transparent Unix WebSocket proxy for the remote-TUI readiness gate.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_THREAD_ID_BYTES: usize = 256;
const COPY_BUFFER_BYTES: usize = 8 * 1024;
const EVENT_CHANNEL_CAPACITY: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

const RELAY_RUNNING: u8 = 0;
const RELAY_DISCONNECTED: u8 = 1;
const RELAY_STOPPING: u8 = 2;

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
    Transport,
    Worker,
    Cleanup,
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
            Self::Transport => "the readiness proxy transport failed",
            Self::Worker => "the readiness proxy worker failed",
            Self::Cleanup => "the readiness proxy socket could not be cleaned up",
        })
    }
}

impl std::error::Error for ReadinessProxyError {}

/// A single-client Unix proxy that remains an opaque relay after readiness.
///
/// `wait_until_ready` succeeds only after the upstream WebSocket upgrade and
/// successful `thread/read` and `thread/resume` responses for the exact target,
/// followed by the expected error round trip for a source-parent `thread/read`.
/// Callers must keep this value alive for the remote TUI's lifetime and call
/// `shutdown` to join both copy pumps and verify socket cleanup.
pub(super) struct ReadinessProxy {
    socket_path: PathBuf,
    socket_identity: SocketIdentity,
    readiness: Receiver<Result<(), ReadinessProxyError>>,
    readiness_result: Option<Result<(), ReadinessProxyError>>,
    lifecycle: Arc<AtomicU8>,
    health: Arc<Mutex<Option<RelayHealth>>>,
    worker: Option<JoinHandle<Result<(), ReadinessProxyError>>>,
    deadline: Instant,
}

#[derive(Clone)]
struct ReadinessExpectation {
    thread_id: String,
    source_thread_id: String,
    cwd: String,
    model: String,
    model_provider: String,
    approval_policy: String,
    approvals_reviewer: String,
    sandbox_type: String,
    sandbox_network_access: bool,
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
            .filter(|cwd| !cwd.is_empty() && cwd.starts_with('/'))
            .ok_or(ReadinessProxyError::InvalidArgument)?;
        Ok(Self {
            thread_id: thread_id.to_owned(),
            source_thread_id: source_thread_id.to_owned(),
            cwd: cwd.to_owned(),
            model: model.to_owned(),
            model_provider: model_provider.to_owned(),
            approval_policy: "never".to_owned(),
            approvals_reviewer: "user".to_owned(),
            sandbox_type: "readOnly".to_owned(),
            sandbox_network_access: false,
        })
    }
}

impl ReadinessProxy {
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
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ReadinessProxyError::InvalidArgument)?;

        verify_private_socket_parent(socket_path)?;
        let listener = UnixListener::bind(socket_path).map_err(|_| ReadinessProxyError::Bind)?;
        let socket_identity = match socket_identity(socket_path) {
            Ok(identity) => identity,
            Err(error) => {
                drop(listener);
                return Err(error);
            }
        };
        if listener.set_nonblocking(true).is_err() {
            drop(listener);
            let _ = remove_owned_socket(socket_path, socket_identity);
            return Err(ReadinessProxyError::Bind);
        }

        let (readiness_sender, readiness) = mpsc::sync_channel(1);
        let lifecycle = Arc::new(AtomicU8::new(RELAY_RUNNING));
        let worker_lifecycle = Arc::clone(&lifecycle);
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
                    listener,
                    &worker_upstream_path,
                    &worker_expectation,
                    deadline,
                    &worker_lifecycle,
                    &worker_health,
                    &readiness_sender,
                );
                proxy_result.and(socket_guard.cleanup())
            })
            .map_err(|_| {
                let _ = remove_owned_socket(socket_path, socket_identity);
                ReadinessProxyError::Worker
            })?;

        Ok(Self {
            socket_path: socket_path.to_owned(),
            socket_identity,
            readiness,
            readiness_result: None,
            lifecycle,
            health,
            worker: Some(worker),
            deadline,
        })
    }

    pub(super) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(super) fn wait_until_ready(&mut self) -> Result<(), ReadinessProxyError> {
        if let Some(result) = self.readiness_result {
            return result;
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
                    RecvTimeoutError::Disconnected => ReadinessProxyError::Worker,
                })
        }) {
            Ok(result) => result,
            Err(error) => Err(error),
        };
        if result.is_err() {
            let _ = self.lifecycle.compare_exchange(
                RELAY_RUNNING,
                RELAY_STOPPING,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        self.readiness_result = Some(result);
        result
    }

    pub(super) fn shutdown(mut self) -> Result<(), ReadinessProxyError> {
        self.stop_and_join()
    }

    /// Proves that the relay has not ended between readiness and the caller's
    /// final process-liveness checks. A worker that ended before intentional
    /// shutdown is always a transport failure, even if readiness was emitted.
    pub(super) fn ensure_connected(&mut self) -> Result<(), ReadinessProxyError> {
        if self.readiness_result != Some(Ok(())) {
            return Err(ReadinessProxyError::UnexpectedSequence);
        }
        if self.lifecycle.load(Ordering::Acquire) != RELAY_RUNNING {
            return Err(ReadinessProxyError::Transport);
        }
        let Some(worker) = self.worker.as_ref() else {
            return Err(ReadinessProxyError::Transport);
        };
        if !worker.is_finished() {
            let health = self
                .health
                .lock()
                .map_err(|_| ReadinessProxyError::Worker)?;
            let health = health.as_ref().ok_or(ReadinessProxyError::Worker)?;
            if health.is_connected()? {
                return Ok(());
            }
            mark_relay_disconnected(&self.lifecycle);
            return Err(ReadinessProxyError::Transport);
        }

        let worker = self.worker.take().ok_or(ReadinessProxyError::Worker)?;
        match worker.join().map_err(|_| ReadinessProxyError::Worker)? {
            Ok(()) => Err(ReadinessProxyError::Transport),
            Err(error) => Err(error),
        }
    }

    fn stop_and_join(&mut self) -> Result<(), ReadinessProxyError> {
        let lifecycle_at_stop = self
            .lifecycle
            .compare_exchange(
                RELAY_RUNNING,
                RELAY_STOPPING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .unwrap_or_else(|state| state);
        let worker_result = match self.worker.take() {
            Some(worker) => worker.join().map_err(|_| ReadinessProxyError::Worker)?,
            None => Ok(()),
        };
        let cleanup_result = remove_owned_socket(&self.socket_path, self.socket_identity);
        if self.readiness_result.is_some_and(|result| result.is_err()) {
            cleanup_result
        } else if lifecycle_at_stop == RELAY_DISCONNECTED {
            cleanup_result.and(Err(ReadinessProxyError::Transport))
        } else {
            cleanup_result.and(worker_result)
        }
    }
}

impl Drop for ReadinessProxy {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

struct RelayHealth {
    client: UnixStream,
    upstream: UnixStream,
}

impl RelayHealth {
    fn is_connected(&self) -> Result<bool, ReadinessProxyError> {
        Ok(socket_is_connected(&self.client)? && socket_is_connected(&self.upstream)?)
    }
}

fn socket_is_connected(stream: &UnixStream) -> Result<bool, ReadinessProxyError> {
    let mut poll_fds = [rustix::event::PollFd::new(
        stream,
        rustix::event::PollFlags::IN,
    )];
    loop {
        match rustix::event::poll(&mut poll_fds, Some(&rustix::event::Timespec::default())) {
            Ok(_) => break,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(ReadinessProxyError::Transport),
        }
    }
    if poll_fds[0].revents().intersects(
        rustix::event::PollFlags::ERR
            | rustix::event::PollFlags::HUP
            | rustix::event::PollFlags::NVAL,
    ) {
        return Ok(false);
    }

    let mut byte = [0_u8; 1];
    loop {
        match rustix::net::recv(
            stream,
            &mut byte[..],
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        ) {
            Ok((_, 0)) => return Ok(false),
            Ok((_, _)) | Err(rustix::io::Errno::AGAIN) => return Ok(true),
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(ReadinessProxyError::Transport),
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
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ReadinessProxyError::Bind);
    }
    Ok(())
}

fn socket_identity(path: &Path) -> Result<SocketIdentity, ReadinessProxyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ReadinessProxyError::Bind)?;
    if !metadata.file_type().is_socket() {
        return Err(ReadinessProxyError::Bind);
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn remove_owned_socket(path: &Path, expected: SocketIdentity) -> Result<(), ReadinessProxyError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ReadinessProxyError::Cleanup),
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
    {
        return Err(ReadinessProxyError::Cleanup);
    }
    fs::remove_file(path).map_err(|_| ReadinessProxyError::Cleanup)
}

struct ReadyNotifier<'a> {
    sender: &'a SyncSender<Result<(), ReadinessProxyError>>,
    sent: bool,
}

impl<'a> ReadyNotifier<'a> {
    fn new(sender: &'a SyncSender<Result<(), ReadinessProxyError>>) -> Self {
        Self {
            sender,
            sent: false,
        }
    }

    fn success(&mut self) -> Result<(), ReadinessProxyError> {
        self.sent = true;
        self.sender
            .send(Ok(()))
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
    lifecycle: &Arc<AtomicU8>,
    health: &Arc<Mutex<Option<RelayHealth>>>,
    readiness_sender: &SyncSender<Result<(), ReadinessProxyError>>,
) -> Result<(), ReadinessProxyError> {
    let mut notifier = ReadyNotifier::new(readiness_sender);
    let result = run_proxy_inner(
        &listener,
        upstream_path,
        expectation,
        deadline,
        lifecycle,
        health,
        &mut notifier,
    );
    if let Err(error) = result {
        notifier.failure(error);
    }
    result
}

fn run_proxy_inner(
    listener: &UnixListener,
    upstream_path: &Path,
    expectation: &ReadinessExpectation,
    deadline: Instant,
    lifecycle: &Arc<AtomicU8>,
    health: &Arc<Mutex<Option<RelayHealth>>>,
    notifier: &mut ReadyNotifier<'_>,
) -> Result<(), ReadinessProxyError> {
    let client = accept_client(listener, deadline, lifecycle)?;
    let upstream = connect_upstream(upstream_path, deadline, lifecycle)?;
    let client_reader = client
        .try_clone()
        .map_err(|_| ReadinessProxyError::Transport)?;
    let client_writer = client
        .try_clone()
        .map_err(|_| ReadinessProxyError::Transport)?;
    let upstream_reader = upstream
        .try_clone()
        .map_err(|_| ReadinessProxyError::Transport)?;
    let upstream_writer = upstream
        .try_clone()
        .map_err(|_| ReadinessProxyError::Transport)?;
    let health_client = client
        .try_clone()
        .map_err(|_| ReadinessProxyError::Transport)?;
    let health_upstream = upstream
        .try_clone()
        .map_err(|_| ReadinessProxyError::Transport)?;
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
    let client_lifecycle = Arc::clone(lifecycle);
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
                &client_lifecycle,
            );
        })
        .map_err(|_| ReadinessProxyError::Worker)?;

    let server_inspecting = Arc::clone(&inspecting);
    let server_order = Arc::clone(&observation_order);
    let server_lifecycle = Arc::clone(lifecycle);
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
                &server_lifecycle,
            );
        }) {
        Ok(pump) => pump,
        Err(_) => {
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
            let _ = client_pump.join();
            return Err(ReadinessProxyError::Worker);
        }
    };

    let mut state = ReadinessState::new(expectation.clone());
    let mut ready = false;
    let result = loop {
        if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING {
            break Ok(());
        }
        if !ready && Instant::now() >= deadline {
            break Err(ReadinessProxyError::Timeout);
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
                    inspecting.store(false, Ordering::Release);
                    notifier.success()?;
                    ready = true;
                }
                Ok(false) => {}
                Err(error) => break Err(error),
            },
            Ok(PumpEvent::Observed(_)) => {}
            Ok(PumpEvent::Ended) if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING => {
                break Ok(());
            }
            Ok(PumpEvent::Ended) => break Err(ReadinessProxyError::Transport),
            Ok(PumpEvent::Failed(_)) if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING => {
                break Ok(());
            }
            Ok(PumpEvent::Failed(error)) => break Err(error),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected)
                if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING =>
            {
                break Ok(());
            }
            Err(RecvTimeoutError::Disconnected) => break Err(ReadinessProxyError::Transport),
        }
    };

    inspecting.store(false, Ordering::Release);
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    drop(event_receiver);
    let client_join = client_pump.join();
    let server_join = server_pump.join();
    if client_join.is_err() || server_join.is_err() {
        return Err(ReadinessProxyError::Worker);
    }
    result
}

fn accept_client(
    listener: &UnixListener,
    deadline: Instant,
    lifecycle: &AtomicU8,
) -> Result<UnixStream, ReadinessProxyError> {
    loop {
        if lifecycle.load(Ordering::Acquire) != RELAY_RUNNING {
            return Err(ReadinessProxyError::Transport);
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(|_| ReadinessProxyError::Transport)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(ReadinessProxyError::Timeout);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(ReadinessProxyError::Accept),
        }
    }
}

fn connect_upstream(
    path: &Path,
    deadline: Instant,
    lifecycle: &AtomicU8,
) -> Result<UnixStream, ReadinessProxyError> {
    loop {
        if lifecycle.load(Ordering::Acquire) != RELAY_RUNNING {
            return Err(ReadinessProxyError::Transport);
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
                    return Err(ReadinessProxyError::Timeout);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(ReadinessProxyError::Connect),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

enum PumpEvent {
    Observed(Box<ObservedEvent>),
    Ended,
    Failed(ReadinessProxyError),
}

fn pump(
    mut reader: UnixStream,
    mut writer: UnixStream,
    direction: Direction,
    inspecting: &AtomicBool,
    sender: &SyncSender<PumpEvent>,
    observation_order: &Mutex<()>,
    lifecycle: &AtomicU8,
) {
    let mut inspector = ProtocolInspector::new(direction);
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => {
                mark_relay_disconnected(lifecycle);
                let _ = sender.send(PumpEvent::Ended);
                return;
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                mark_relay_disconnected(lifecycle);
                let _ = sender.send(PumpEvent::Failed(ReadinessProxyError::Transport));
                return;
            }
        };
        let bytes = &buffer[..count];
        if !inspecting.load(Ordering::Acquire) {
            if writer.write_all(bytes).is_err() {
                mark_relay_disconnected(lifecycle);
                let _ = sender.send(PumpEvent::Failed(ReadinessProxyError::Transport));
                return;
            }
            continue;
        }

        let events = match inspector.feed(bytes) {
            Ok(events) => events,
            Err(error) => {
                mark_relay_disconnected(lifecycle);
                let _ = sender.send(PumpEvent::Failed(error));
                return;
            }
        };
        let Ok(_ordering_guard) = observation_order.lock() else {
            mark_relay_disconnected(lifecycle);
            let _ = sender.send(PumpEvent::Failed(ReadinessProxyError::Worker));
            return;
        };
        if writer.write_all(bytes).is_err() || send_observed(events, sender).is_err() {
            mark_relay_disconnected(lifecycle);
            let _ = sender.send(PumpEvent::Failed(ReadinessProxyError::Transport));
            return;
        }
    }
}

fn mark_relay_disconnected(lifecycle: &AtomicU8) {
    let _ = lifecycle.compare_exchange(
        RELAY_RUNNING,
        RELAY_DISCONNECTED,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
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

        self.handshake.extend_from_slice(bytes);
        let Some(header_end) = find_header_end(&self.handshake) else {
            if self.handshake.len() > MAX_HANDSHAKE_BYTES {
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
        bytes: &[u8],
        events: &mut Vec<ObservedEvent>,
    ) -> Result<(), ReadinessProxyError> {
        self.buffer.extend_from_slice(bytes);
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
            0x8 => return Err(ReadinessProxyError::Transport),
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
        settings: Option<ObservedThreadSettings>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedThreadSettings {
    cwd: String,
    model: String,
    model_provider: String,
    approval_policy: String,
    approvals_reviewer: String,
    sandbox_type: String,
    sandbox_network_access: bool,
}

fn inspect_message(
    direction: Direction,
    bytes: &[u8],
    events: &mut Vec<ObservedEvent>,
) -> Result<(), ReadinessProxyError> {
    let message: Value =
        serde_json::from_slice(bytes).map_err(|_| ReadinessProxyError::InvalidMessage)?;
    let Some(object) = message.as_object() else {
        return Err(ReadinessProxyError::InvalidMessage);
    };
    match direction {
        Direction::ClientToServer => {
            let method = match object.get("method").and_then(Value::as_str) {
                Some("thread/read") => ReadinessMethod::ThreadRead,
                Some("thread/resume") => ReadinessMethod::ThreadResume,
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
                .ok_or(ReadinessProxyError::InvalidMessage)?;
            let include_turns = match params.get("includeTurns") {
                Some(value) => Some(value.as_bool().ok_or(ReadinessProxyError::InvalidMessage)?),
                None => None,
            };
            events.push(ObservedEvent::Request {
                id,
                method,
                thread_id: thread_id.to_owned(),
                include_turns,
            });
        }
        Direction::ServerToClient => {
            if object.contains_key("method") {
                return Ok(());
            }
            let Some(id) = object.get("id") else {
                return Ok(());
            };
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
            let thread_id = object
                .get("result")
                .and_then(|result| result.get("thread"))
                .and_then(|thread| thread.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let settings = object.get("result").and_then(parse_thread_settings);
            events.push(ObservedEvent::Response {
                id: id.clone(),
                has_error,
                thread_id,
                settings,
            });
        }
    }
    Ok(())
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

fn parse_thread_settings(result: &Value) -> Option<ObservedThreadSettings> {
    let result = result.as_object()?;
    let sandbox = result.get("sandbox")?.as_object()?;
    if sandbox.len() != 2 {
        return None;
    }
    Some(ObservedThreadSettings {
        cwd: result.get("cwd")?.as_str()?.to_owned(),
        model: result.get("model")?.as_str()?.to_owned(),
        model_provider: result.get("modelProvider")?.as_str()?.to_owned(),
        approval_policy: result.get("approvalPolicy")?.as_str()?.to_owned(),
        approvals_reviewer: result.get("approvalsReviewer")?.as_str()?.to_owned(),
        sandbox_type: sandbox.get("type")?.as_str()?.to_owned(),
        sandbox_network_access: sandbox.get("networkAccess")?.as_bool()?,
    })
}

fn valid_request_id(id: &Value) -> bool {
    id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()
}

enum ReadinessPhase {
    AwaitReadRequest,
    AwaitReadResponse(Value),
    AwaitResumeRequest,
    AwaitResumeResponse(Value),
    AwaitPostResumeReadRequest,
    AwaitPostResumeReadResponse(Value),
    Ready,
}

struct ReadinessState {
    expectation: ReadinessExpectation,
    client_handshake: bool,
    server_handshake: bool,
    phase: ReadinessPhase,
}

impl ReadinessState {
    fn new(expectation: ReadinessExpectation) -> Self {
        Self {
            expectation,
            client_handshake: false,
            server_handshake: false,
            phase: ReadinessPhase::AwaitReadRequest,
        }
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
                    (ReadinessPhase::AwaitPostResumeReadRequest, ReadinessMethod::ThreadRead) => {
                        if thread_id != self.expectation.source_thread_id || include_turns.is_some()
                        {
                            return Err(ReadinessProxyError::TargetMismatch);
                        }
                        self.phase = ReadinessPhase::AwaitPostResumeReadResponse(id);
                        Ok(false)
                    }
                    _ => Err(ReadinessProxyError::UnexpectedSequence),
                }
            }
            ObservedEvent::Response {
                id,
                has_error,
                thread_id,
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
                    validate_resume_settings(settings.as_ref(), &self.expectation)?;
                    self.phase = ReadinessPhase::AwaitPostResumeReadRequest;
                    Ok(false)
                }
                ReadinessPhase::AwaitPostResumeReadResponse(expected_id) if id == *expected_id => {
                    // The synthetic parent lives only in the isolated source
                    // home, so the target app-server must reject this metadata
                    // lookup. The TUI handles that error and continues; seeing
                    // the request proves it deserialized the resume ancestry.
                    if !has_error || thread_id.is_some() {
                        return Err(ReadinessProxyError::InvalidMessage);
                    }
                    self.phase = ReadinessPhase::Ready;
                    Ok(true)
                }
                _ => Ok(matches!(self.phase, ReadinessPhase::Ready)),
            },
        }
    }
}

fn validate_resume_settings(
    actual: Option<&ObservedThreadSettings>,
    expected: &ReadinessExpectation,
) -> Result<(), ReadinessProxyError> {
    let Some(actual) = actual else {
        return Err(ReadinessProxyError::InvalidMessage);
    };
    if actual.cwd == expected.cwd
        && actual.model == expected.model
        && actual.model_provider == expected.model_provider
        && actual.approval_policy == expected.approval_policy
        && actual.approvals_reviewer == expected.approvals_reviewer
        && actual.sandbox_type == expected.sandbox_type
        && actual.sandbox_network_access == expected.sandbox_network_access
    {
        Ok(())
    } else {
        Err(ReadinessProxyError::TargetMismatch)
    }
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
    use std::error::Error;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    const TARGET_THREAD_ID: &str = "019f64a7-c5d1-7ed1-aca8-156bc32b650c";
    const SOURCE_THREAD_ID: &str = "019f64a7-c5d1-7ed1-aca8-156bc32b650b";
    const TARGET_CWD: &str = "/synthetic/workspace";
    const TARGET_MODEL: &str = "calcifer-handoff-smoke";
    const TARGET_MODEL_PROVIDER: &str = "calcifer_smoke";

    fn expectation() -> ReadinessExpectation {
        ReadinessExpectation {
            thread_id: TARGET_THREAD_ID.to_owned(),
            source_thread_id: SOURCE_THREAD_ID.to_owned(),
            cwd: TARGET_CWD.to_owned(),
            model: TARGET_MODEL.to_owned(),
            model_provider: TARGET_MODEL_PROVIDER.to_owned(),
            approval_policy: "never".to_owned(),
            approvals_reviewer: "user".to_owned(),
            sandbox_type: "readOnly".to_owned(),
            sandbox_network_access: false,
        }
    }

    fn observed_settings() -> ObservedThreadSettings {
        ObservedThreadSettings {
            cwd: TARGET_CWD.to_owned(),
            model: TARGET_MODEL.to_owned(),
            model_provider: TARGET_MODEL_PROVIDER.to_owned(),
            approval_policy: "never".to_owned(),
            approvals_reviewer: "user".to_owned(),
            sandbox_type: "readOnly".to_owned(),
            sandbox_network_access: false,
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
                    settings: None,
                },
            ]
        );
        Ok(())
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
                settings: None,
            }),
            Err(ReadinessProxyError::InvalidMessage)
        );

        let expected = observed_settings();
        let mutations = [
            ObservedThreadSettings {
                cwd: "/outside".to_owned(),
                ..expected.clone()
            },
            ObservedThreadSettings {
                model: "other".to_owned(),
                ..expected.clone()
            },
            ObservedThreadSettings {
                model_provider: "other".to_owned(),
                ..expected.clone()
            },
            ObservedThreadSettings {
                approval_policy: "on-request".to_owned(),
                ..expected.clone()
            },
            ObservedThreadSettings {
                approvals_reviewer: "auto_review".to_owned(),
                ..expected.clone()
            },
            ObservedThreadSettings {
                sandbox_type: "workspaceWrite".to_owned(),
                ..expected.clone()
            },
            ObservedThreadSettings {
                sandbox_network_access: true,
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
        proxy.shutdown()?;
        drop(client);
        server
            .join()
            .map_err(|_| io::Error::other("mock app-server panicked"))??;
        assert!(!proxy_path.exists());
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

        for _ in 0..100 {
            if proxy.lifecycle.load(Ordering::Acquire) == RELAY_DISCONNECTED {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(proxy.lifecycle.load(Ordering::Acquire), RELAY_DISCONNECTED);
        assert_eq!(
            proxy.ensure_connected(),
            Err(ReadinessProxyError::Transport)
        );
        assert_eq!(proxy.shutdown(), Err(ReadinessProxyError::Transport));
        server
            .join()
            .map_err(|_| io::Error::other("mock app-server panicked"))??;
        Ok(())
    }

    #[test]
    fn active_health_probe_detects_eof_without_waiting_for_the_copy_pump() -> io::Result<()> {
        let (stream, peer) = UnixStream::pair()?;
        assert!(socket_is_connected(&stream).map_err(io::Error::other)?);
        drop(peer);
        assert!(!socket_is_connected(&stream).map_err(io::Error::other)?);
        Ok(())
    }

    #[test]
    fn active_health_probe_detects_hangup_behind_buffered_data() -> io::Result<()> {
        let (stream, mut peer) = UnixStream::pair()?;
        peer.write_all(b"buffered")?;
        peer.shutdown(Shutdown::Both)?;
        assert!(!socket_is_connected(&stream).map_err(io::Error::other)?);
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

        assert_eq!(proxy.shutdown(), Err(ReadinessProxyError::Cleanup));
        assert_eq!(fs::read(&proxy_path)?, b"replacement");
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
    fn timeout_fails_closed_and_removes_the_listener_socket() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let mut proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_millis(40))?;

        assert_eq!(proxy.wait_until_ready(), Err(ReadinessProxyError::Timeout));
        proxy.shutdown()?;
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
