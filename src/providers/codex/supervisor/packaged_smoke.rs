//! Credential-free smoke tests against the checksum-pinned official Codex package.

use std::collections::{BTreeSet, VecDeque};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use tungstenite::client::client_with_config;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket, accept_with_config};
use uuid::Uuid;

use fs2::FileExt;

use super::channel::{
    LifecycleEndpoint, LifecyclePair, spawn_guardian_with_lifecycle_stdin_and_completion,
};
use super::coordinator::{
    CoordinatorBounds, CoordinatorRunOutcome, CoordinatorTerminalReport, ProductionCoordinator,
};
use super::coordinator_terminal::CoordinatorTerminal;
use super::entry::{
    AnchorCompletion, CompletionError, CompletionPair, CompletionPoll, CompletionTransit,
    GuardianCompletion, RecoveryCheckpoint,
};
use super::guardian::{
    GuardianBounds, GuardianRunOutcome, GuardianSetupError, PACKAGED_APP_NOT_STARTED_MARKER,
    PACKAGED_GUARDIAN_STARTUP_ARMED_MARKER, PACKAGED_STARTUP_FAILURE_MARKERS,
    PACKAGED_TUI_NOT_STARTED_MARKER, PackagedGuardianSeams, ProductionGuardianConfig,
    run_production_guardian_with_test_seams, write_packaged_startup_failure_marker,
};
use super::process::{ManagedGroupChild, shutdown_app_server_child};
use super::protocol::{
    ChildDisposition, ChildRole, CleanupStatus, GuardianExitDisposition, SessionStatus, StopAction,
    WorkerJoinStatus,
};
use super::provider::MonitorSessionCapability;
use super::runtime::validate_packaged_runtime_parent;
use super::session::{
    PACKAGED_SESSION_RETAINED_OPERATION_MARKERS, PACKAGED_SESSION_STARTUP_FAILURE_MARKERS,
    PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS, PACKAGED_TUI_OUTPUT_SENTINEL,
    PackagedObservationIntegrityFailure, PackagedObservedGuardianExit,
    PackagedObservedOperationError, PackagedObservedSessionStatus,
    PackagedObservedTerminationCause, PackagedObservedTuiDisposition, PackagedObservedWorkerJoin,
    PackagedSessionObservation, PackagedTuiOutputMatcher, arm_packaged_session_observation,
    take_packaged_session_observation,
};
use super::startup::{PACKAGED_APP_SOCKET_FAILURE_MARKERS, PACKAGED_COMPATIBILITY_FAILURE_MARKERS};
use super::terminal::{
    PtyMaster, PtyOwner, RecoveryTty, TerminalChannelPair, TerminalEndpoint, TerminalSize,
    claim_controlling_terminal_from_stdin, termios_semantically_equal,
    verify_controlling_terminal_from_stdin,
};
use crate::profiles::{CoordinatorProfileLease, Provider, Registry, TargetGuardianLease};
use crate::providers::codex::{
    CodexIdentityAdapter, CodexUsageError, MANAGED_ENVIRONMENT_DENYLIST, managed_command,
    monitor::{MonitorAction, MonitorCommand, MonitorError, MonitorProtocol},
    sanitize_managed_environment, validate_initialize_result,
};

const PACKAGE_BINARY_ENV: &str = "CALCIFER_CODEX_COMPAT_BINARY";
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const PACKAGE_BACKEND_INITIAL_READ_TIMEOUT: Duration = Duration::from_secs(1);
const PACKAGE_BACKEND_READ_SLICE: Duration = Duration::from_millis(100);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
const GRACE_OBSERVATION: Duration = Duration::from_millis(300);
const MAX_HTTP_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_TOOL_PROBE_BYTES: usize = 16 * 1024;
const PACKAGE_SCRATCH_CREATE_ATTEMPTS: usize = 8;
const PRIVATE_ATOMIC_PUBLISH_ATTEMPTS: usize = 8;
const TOOL_PROBE_VERSION: u8 = 1;
const TOOL_PROBE_MAGIC_ENV: &str = "CALCIFER_PACKAGE_TOOL_PROBE";
const TOOL_PROBE_MANIFEST_ENV: &str = "CALCIFER_PACKAGE_TOOL_MANIFEST";
const TOOL_PROBE_REPORT_ENV: &str = "CALCIFER_PACKAGE_TOOL_REPORT";
const TOOL_PROBE_RELEASE_ENV: &str = "CALCIFER_PACKAGE_TOOL_RELEASE";
const TOOL_PROBE_LIFETIME_ENV: &str = "CALCIFER_PACKAGE_TOOL_LIFETIME";
const TOOL_PROBE_CHILD_TEST: &str =
    "providers::codex::supervisor::packaged_smoke::packaged_codex_detached_tool_probe_child";
const SUPERVISOR_AUTHORITY_DESCRIPTOR_COUNT: usize = 8;
const PACKAGE_MONITOR_THREAD_ID: &str = "019c7714-3b77-74d1-9866-e1f484aae2ab";
const PACKAGE_FAKE_ACCESS_TOKEN: &str = "calcifer-package-access";
const PACKAGE_FAKE_ACCOUNT_ID: &str = "calcifer-package-account";
const PACKAGE_FAKE_ID_TOKEN: &str = concat!(
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.",
    "eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaWQiOiJjYWxjaWZlci1wYWNrYWdlLWFjY291bnQifX0.",
    "c2lnbmF0dXJl"
);

fn package_process_test_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn require_rejected_test_result<T, E>(
    result: Result<T, E>,
    accepted_message: &'static str,
) -> Result<E, Box<dyn Error>> {
    match result {
        Err(error) => Ok(error),
        Ok(_) => Err(accepted_message.into()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetachedToolLaunchState {
    NotRequested,
    AmbiguousOrStarted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetachedToolFailureCleanupDecision {
    Finite,
    RequireProcessProofOrPark,
}

const fn detached_tool_failure_cleanup_decision(
    state: DetachedToolLaunchState,
) -> DetachedToolFailureCleanupDecision {
    match state {
        DetachedToolLaunchState::NotRequested => DetachedToolFailureCleanupDecision::Finite,
        DetachedToolLaunchState::AmbiguousOrStarted => {
            DetachedToolFailureCleanupDecision::RequireProcessProofOrPark
        }
    }
}

/// Package-only transport wrapper that observes no payload and retains only a
/// bounded boolean: whether the current request epoch completed any successful
/// underlying write. Handshake and ordinary RPC traffic run with no active
/// epoch and therefore cannot influence detached-tool classification.
struct ToolRequestWriteObserver<S> {
    inner: S,
    request_epoch_active: bool,
    request_epoch_wrote_bytes: bool,
}

impl<S> ToolRequestWriteObserver<S> {
    const fn new(inner: S) -> Self {
        Self {
            inner,
            request_epoch_active: false,
            request_epoch_wrote_bytes: false,
        }
    }

    fn begin_request_epoch(&mut self) {
        self.request_epoch_active = true;
        self.request_epoch_wrote_bytes = false;
    }

    fn end_request_epoch(&mut self) {
        self.request_epoch_active = false;
    }

    const fn request_epoch_wrote_bytes(&self) -> bool {
        self.request_epoch_active && self.request_epoch_wrote_bytes
    }
}

impl<S: Read> Read for ToolRequestWriteObserver<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl<S: Write> Write for ToolRequestWriteObserver<S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        if self.request_epoch_active && written > 0 {
            self.request_epoch_wrote_bytes = true;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

type PackageAppStream = ToolRequestWriteObserver<UnixStream>;
type PackageAppWebSocket = WebSocket<PackageAppStream>;

/// Fully serialized and size-bounded before the WebSocket is touched. This is
/// intentionally move-only: one prepared shell-command request can cross the
/// observed send boundary at most once.
struct PreparedToolRequest {
    encoded: String,
}

impl PreparedToolRequest {
    fn shell_command(thread_id: String, command: String) -> Result<Self, Box<dyn Error>> {
        let encoded = serde_json::to_string(&json!({
            "id": 3,
            "method": "thread/shellCommand",
            "params": {
                "threadId": thread_id,
                "command": command
            }
        }))?;
        if encoded.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
            return Err("prepared tool request exceeded the package bound".into());
        }
        Ok(Self { encoded })
    }

    fn into_message(self) -> Message {
        Message::text(self.encoded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedToolSendFailure {
    launch_state: DetachedToolLaunchState,
}

impl PreparedToolSendFailure {
    const fn launch_state(&self) -> DetachedToolLaunchState {
        self.launch_state
    }
}

impl fmt::Display for PreparedToolSendFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the prepared detached-tool request could not be sent")
    }
}

impl Error for PreparedToolSendFailure {}

struct PreparedToolSendSuccess<S> {
    websocket: WebSocket<ToolRequestWriteObserver<S>>,
}

impl<S> PreparedToolSendSuccess<S> {
    const fn launch_state(&self) -> DetachedToolLaunchState {
        DetachedToolLaunchState::AmbiguousOrStarted
    }

    fn into_websocket(self) -> WebSocket<ToolRequestWriteObserver<S>> {
        self.websocket
    }
}

/// Consumes both values. Any failure drops the WebSocket in this function, so
/// tungstenite cannot later flush a buffered shell-command frame. Classification
/// depends only on observed successful write bytes, never on error variants.
fn send_prepared_tool_request<S: Read + Write>(
    mut websocket: WebSocket<ToolRequestWriteObserver<S>>,
    request: PreparedToolRequest,
) -> Result<PreparedToolSendSuccess<S>, PreparedToolSendFailure> {
    if websocket.flush().is_err() {
        return Err(PreparedToolSendFailure {
            launch_state: DetachedToolLaunchState::NotRequested,
        });
    }

    websocket.get_mut().begin_request_epoch();
    match websocket.send(request.into_message()) {
        Ok(()) => {
            websocket.get_mut().end_request_epoch();
            Ok(PreparedToolSendSuccess { websocket })
        }
        Err(_) => {
            let launch_state = if websocket.get_ref().request_epoch_wrote_bytes() {
                DetachedToolLaunchState::AmbiguousOrStarted
            } else {
                DetachedToolLaunchState::NotRequested
            };
            Err(PreparedToolSendFailure { launch_state })
        }
    }
}

#[derive(Clone, Copy)]
enum ScriptedWriteStep {
    Error,
    Bytes(usize),
    All,
}

#[derive(Clone, Copy)]
enum ScriptedFlushStep {
    Error,
    Ok,
}

struct ScriptedToolTransport {
    writes: std::collections::VecDeque<ScriptedWriteStep>,
    flushes: std::collections::VecDeque<ScriptedFlushStep>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ScriptedToolTransport {
    fn websocket(
        writes: impl IntoIterator<Item = ScriptedWriteStep>,
        flushes: impl IntoIterator<Item = ScriptedFlushStep>,
    ) -> (
        WebSocket<ToolRequestWriteObserver<Self>>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let transport = Self {
            writes: writes.into_iter().collect(),
            flushes: flushes.into_iter().collect(),
            dropped: dropped.clone(),
        };
        (
            WebSocket::from_raw_socket(
                ToolRequestWriteObserver::new(transport),
                tungstenite::protocol::Role::Client,
                None,
            ),
            dropped,
        )
    }
}

impl Read for ScriptedToolTransport {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "scripted"))
    }
}

impl Write for ScriptedToolTransport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self.writes.pop_front().unwrap_or(ScriptedWriteStep::All) {
            ScriptedWriteStep::Error => Err(io::Error::new(io::ErrorKind::BrokenPipe, "scripted")),
            ScriptedWriteStep::Bytes(count) => Ok(count.min(buffer.len())),
            ScriptedWriteStep::All => Ok(buffer.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.flushes.pop_front().unwrap_or(ScriptedFlushStep::Ok) {
            ScriptedFlushStep::Error => Err(io::Error::new(io::ErrorKind::BrokenPipe, "scripted")),
            ScriptedFlushStep::Ok => Ok(()),
        }
    }
}

impl Drop for ScriptedToolTransport {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn prepared_scripted_tool_request() -> Result<PreparedToolRequest, Box<dyn Error>> {
    PreparedToolRequest::shell_command("test-thread".to_owned(), "true".to_owned())
}

#[test]
fn detached_tool_preflush_failure_is_definitely_unsent_and_drops_socket()
-> Result<(), Box<dyn Error>> {
    let request = prepared_scripted_tool_request()?;
    let (websocket, dropped) = ScriptedToolTransport::websocket([], [ScriptedFlushStep::Error]);
    let failure = send_prepared_tool_request(websocket, request)
        .err()
        .ok_or("scripted preflush unexpectedly succeeded")?;
    assert_eq!(
        failure.launch_state(),
        DetachedToolLaunchState::NotRequested
    );
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

#[test]
fn detached_tool_first_write_error_is_definitely_unsent_and_drops_socket()
-> Result<(), Box<dyn Error>> {
    let request = prepared_scripted_tool_request()?;
    let (websocket, dropped) =
        ScriptedToolTransport::websocket([ScriptedWriteStep::Error], [ScriptedFlushStep::Ok]);
    let failure = send_prepared_tool_request(websocket, request)
        .err()
        .ok_or("scripted first write unexpectedly succeeded")?;
    assert_eq!(
        failure.launch_state(),
        DetachedToolLaunchState::NotRequested
    );
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

#[test]
fn detached_tool_partial_write_error_is_ambiguous_and_drops_socket() -> Result<(), Box<dyn Error>> {
    let request = prepared_scripted_tool_request()?;
    let (websocket, dropped) = ScriptedToolTransport::websocket(
        [ScriptedWriteStep::Bytes(1), ScriptedWriteStep::Error],
        [ScriptedFlushStep::Ok],
    );
    let failure = send_prepared_tool_request(websocket, request)
        .err()
        .ok_or("scripted partial write unexpectedly succeeded")?;
    assert_eq!(
        failure.launch_state(),
        DetachedToolLaunchState::AmbiguousOrStarted
    );
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

#[test]
fn detached_tool_full_frame_then_flush_error_is_ambiguous_and_drops_socket()
-> Result<(), Box<dyn Error>> {
    let request = prepared_scripted_tool_request()?;
    let (websocket, dropped) = ScriptedToolTransport::websocket(
        [ScriptedWriteStep::All],
        [ScriptedFlushStep::Ok, ScriptedFlushStep::Error],
    );
    let failure = send_prepared_tool_request(websocket, request)
        .err()
        .ok_or("scripted flush unexpectedly succeeded")?;
    assert_eq!(
        failure.launch_state(),
        DetachedToolLaunchState::AmbiguousOrStarted
    );
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

#[test]
fn detached_tool_success_is_ambiguous_and_retains_socket() -> Result<(), Box<dyn Error>> {
    let request = prepared_scripted_tool_request()?;
    let (websocket, dropped) = ScriptedToolTransport::websocket(
        [ScriptedWriteStep::All],
        [ScriptedFlushStep::Ok, ScriptedFlushStep::Ok],
    );
    let sent = send_prepared_tool_request(websocket, request)
        .map_err(|_| "scripted tool request unexpectedly failed")?;
    assert_eq!(
        sent.launch_state(),
        DetachedToolLaunchState::AmbiguousOrStarted
    );
    assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
    drop(sent.into_websocket());
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

#[test]
fn detached_tool_cleanup_is_finite_only_when_definitely_unsent() {
    assert_eq!(
        detached_tool_failure_cleanup_decision(DetachedToolLaunchState::NotRequested),
        DetachedToolFailureCleanupDecision::Finite
    );
    assert_eq!(
        detached_tool_failure_cleanup_decision(DetachedToolLaunchState::AmbiguousOrStarted),
        DetachedToolFailureCleanupDecision::RequireProcessProofOrPark
    );
}

#[test]
fn prepared_tool_request_is_bounded_before_transport_access() {
    let oversized = "x".repeat(MAX_WEBSOCKET_MESSAGE_BYTES);
    assert!(PreparedToolRequest::shell_command("test-thread".to_owned(), oversized).is_err());
}
const PACKAGE_SUPERVISOR_ROLE_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_ROLE";
const PACKAGE_SUPERVISOR_ROOT_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_ROOT";
const PACKAGE_SUPERVISOR_BACKEND_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_BACKEND";
const PACKAGE_SUPERVISOR_CODEX_HOME_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_CODEX_HOME";
const PACKAGE_SUPERVISOR_PROFILE_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_PROFILE";
const PACKAGE_SUPERVISOR_RUNTIME_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_RUNTIME";
const PACKAGE_SUPERVISOR_REPORT_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_REPORT";
const PACKAGE_SUPERVISOR_FOREGROUND_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_FOREGROUND";
const PACKAGE_SUPERVISOR_RECOVERY_CHECKPOINT_ENV: &str =
    "CALCIFER_PACKAGE_SUPERVISOR_RECOVERY_CHECKPOINT";
const PACKAGE_SUPERVISOR_PROVIDER_TARGET_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_PROVIDER_TARGET";
const PACKAGE_SUPERVISOR_STARTUP_FAULT_ENV: &str = "CALCIFER_PACKAGE_SUPERVISOR_STARTUP_FAULT";
const PACKAGE_SUPERVISOR_COORDINATOR_ROLE: &str = "coordinator-v1";
const PACKAGE_SUPERVISOR_GUARDIAN_ROLE: &str = "guardian-v1";
const PACKAGE_SUPERVISOR_HELPER_TEST: &str = concat!(
    "providers::codex::supervisor::packaged_smoke::",
    "packaged_codex_official_tui_production_graph_helper"
);
const PACKAGE_LIBTEST_PROVIDER_HELPER_TEST: &str = concat!(
    "providers::codex::supervisor::packaged_smoke::",
    "packaged_codex_libtest_provider_helper"
);
const PACKAGE_LIBTEST_LAUNCHER_HELPER_TEST: &str = concat!(
    "providers::codex::supervisor::packaged_smoke::",
    "packaged_codex_libtest_launcher_helper"
);
const PACKAGE_TUI_LAUNCHER_ENV: &str = "CALCIFER_PACKAGE_TUI_LAUNCHER";
const PACKAGE_LIBTEST_PROVIDER_ROLE_ENV: &str = "CALCIFER_PACKAGE_LIBTEST_PROVIDER_ROLE";
const PACKAGE_LIBTEST_PROVIDER_APP_SOCKET_ENV: &str =
    "CALCIFER_PACKAGE_LIBTEST_PROVIDER_APP_SOCKET";
const PACKAGE_LIBTEST_PROVIDER_REMOTE_ENV: &str = "CALCIFER_PACKAGE_LIBTEST_PROVIDER_REMOTE";
const PACKAGE_LIBTEST_PROVIDER_THREAD_ENV: &str = "CALCIFER_PACKAGE_LIBTEST_PROVIDER_THREAD";
const PACKAGE_LIBTEST_PROVIDER_ROOT_ENV: &str = "CALCIFER_PACKAGE_LIBTEST_PROVIDER_ROOT";
const PACKAGE_LIBTEST_PROVIDER_APP_ROLE: &str = "app-server-v1";
const PACKAGE_LIBTEST_PROVIDER_TUI_ROLE: &str = "remote-tui-v1";
const PACKAGE_LIBTEST_PROVIDER_WRAPPER: &str = "codex-libtest-provider";
const PACKAGE_LIBTEST_LAUNCHER_WRAPPER: &str = "tui-libtest-launcher";
const PACKAGE_LIBTEST_PROVIDER_MAX_INPUT_BYTES: usize = 64 * 1024;
const PACKAGE_LIBTEST_PROVIDER_MAX_CONNECTIONS: usize = 8;
const PACKAGE_LIBTEST_PROVIDER_MAX_MONITOR_READS: u64 = 64;
const PACKAGE_SUPERVISOR_THREAD_ID: &str = "019f6794-b252-7d31-96a8-6ed763b9a752";
const PACKAGE_SUPERVISOR_MODEL: &str = "calcifer-package-smoke";
const PACKAGE_SUPERVISOR_MODEL_PROVIDER: &str = "calcifer_package_smoke";
const PACKAGE_SUPERVISOR_STARTUP_SENTINEL: &str = "calcifer package startup history sentinel";
const PACKAGE_SUPERVISOR_INITIAL_PROMPT: &str = "calcifer-initial-gate-sentinel";
const PACKAGE_TUI_BRACKETED_PASTE_START: &[u8] = b"\x1b[200~";
const PACKAGE_TUI_BRACKETED_PASTE_END: &[u8] = b"\x1b[201~";
const PACKAGE_SUPERVISOR_INITIAL_INPUT: &[u8] =
    b"\x1b[200~calcifer-initial-gate-sentinel\x1b[201~\r";
const PACKAGE_SUPERVISOR_PRE_READY_INPUT: &[u8] = b"calcifer-pre-ready-sentinel\r";
const PACKAGE_SUPERVISOR_SUSPENDED_INPUT: &[u8] = b"calcifer-suspended-sentinel\r";
const PACKAGE_SUPERVISOR_EXIT_INPUT: &[u8] = b"\x1b[200~/quit\x1b[201~\r";
const PACKAGE_SUPERVISOR_INITIAL_SIZE: TerminalSize = TerminalSize::new(37, 111);
const PACKAGE_SUPERVISOR_RESIZED_SIZE: TerminalSize = TerminalSize::new(41, 123);
const PACKAGE_SUPERVISOR_RESUMED_SIZE: TerminalSize = TerminalSize::new(43, 125);
const PACKAGE_SUPERVISOR_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const PACKAGE_PS_PROCESS_FIELDS: &str = "pid=,pgid=,uid=,state=";
// Debug builds hash the large official executable more than once with the
// portable SHA-256 implementation. Measured package runs can still be in the
// final pre-TUI revalidation after four minutes, so the package-only phase and
// startup bound is deliberately wider than production's unchanged defaults.
const PACKAGE_SUPERVISOR_COMPATIBILITY_TIMEOUT: Duration = Duration::from_secs(180);
const PACKAGE_SUPERVISOR_STARTUP_TIMEOUT: Duration = Duration::from_secs(600);
// The deterministic path still traverses compatibility, App, monitor, TUI
// planning, and descriptor gates before the relay starts. Reserve a bounded
// pre-relay interval plus the fixture's target-specific relay interval. If
// pre-relay work exceeds its reserve, startup rejects the generation before
// either relay or TUI spawn instead of manufacturing a shorter relay window.
const PACKAGE_DETERMINISTIC_PRE_RELAY_STARTUP_RESERVE: Duration = Duration::from_secs(15);
const PACKAGE_DETERMINISTIC_RELAY_START_TIMEOUT: Duration = Duration::from_secs(30);
const PACKAGE_DETERMINISTIC_SUPERVISOR_TIMEOUT: Duration = Duration::from_secs(45);
// After the parent observes the Guardian's durable, private startup-arm
// acknowledgement, retained recovery reserves this separately named
// package-only handoff/report margin beyond the Guardian's complete startup
// interval. The observation can only move recovery later and grants no
// process, signal, deletion, or retry authority. This does not change the
// Guardian's production startup timeout.
const PACKAGE_PARENT_STARTUP_HANDOFF_MARGIN: Duration = Duration::from_secs(100);
// Every deterministic generation reserves its complete external fence before
// creating scratch, sockets, descriptors, or processes. Unused real time is
// returned after exact cleanup. This in-process pool is an early admission and
// accounting guard, not an authoritative wall-clock timeout: a single stalled
// generation cannot return its lease. Unix CI therefore wraps the ordinary
// libtest execution and the repeated MSRV command in process-group watchdogs.
// Static CI validation binds one ordinary slot and two MSRV suite slots to this
// fence, including each watchdog's fixed TERM grace and bounded post-KILL reap.
const PACKAGE_DETERMINISTIC_SUITE_TIMEOUT: Duration = Duration::from_secs(360);
// CI validates this fixed internal fence against a later per-command watchdog
// and an even later dedicated-job timeout. One fence is recorded when the
// package generation starts. Every exercise wait is capped at that fence's
// fixed recovery start so drip progress cannot consume cleanup's reserved
// budget or manufacture a fresh outer lifetime.
const PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT: Duration = Duration::from_secs(25 * 60);
const PACKAGE_DETERMINISTIC_EXTERNAL_HARD_TIMEOUT: Duration = Duration::from_secs(105);
// The backend starts slightly before the generation fence is recorded. Its
// extra minute prevents its own EOF from becoming an earlier cleanup trigger;
// the generation owner or the outer job remains the authoritative boundary.
const PACKAGE_SESSION_BACKEND_START_MARGIN: Duration = Duration::from_secs(60);
const PACKAGE_SESSION_BACKEND_TIMEOUT: Duration = Duration::from_secs(26 * 60);
const PACKAGE_CLEANUP_NORMAL_COMPLETION_RACE: Duration = Duration::from_millis(100);
const PACKAGE_CLEANUP_RECOVERY_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
// A failed deterministic drive may race a checkpoint that the guardian has
// already committed to publish. Reconcile that exact frame for one bounded
// diagnostic window before consuming the recovery boundary; never wait for
// the much wider ordinary startup allowance after the drive itself failed.
const PACKAGE_SELECTED_RECOVERY_RECONCILIATION_TIMEOUT: Duration = Duration::from_secs(10);
const PACKAGE_FIXED_FAILURE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const PACKAGE_CLEANUP_STARTUP_RECOVERY_MARGIN: Duration = Duration::from_secs(100);
// A request can arrive while the package guardian is still inside its 600s
// startup bound and its one retained-owner retry can then traverse shutdown.
// Keep the direct coordinator completely unsignaled across that full window.
const PACKAGE_CLEANUP_HEALTHY_LIFECYCLE_GRACE: Duration = Duration::from_secs(700);
const PACKAGE_CLEANUP_COORDINATOR_TERM_GRACE: Duration = Duration::from_secs(5);
const PACKAGE_CLEANUP_COORDINATOR_KILL_WAIT: Duration = Duration::from_secs(5);
const PACKAGE_CLEANUP_COMPLETION_PROOF_TIMEOUT: Duration = Duration::from_secs(10);
const PACKAGE_CLEANUP_GROUP_PROOF_TIMEOUT: Duration = Duration::from_secs(10);
const PACKAGE_CLEANUP_EXTERNAL_OBSERVATION_MARGIN: Duration = Duration::from_secs(10);
const PACKAGE_DETERMINISTIC_CLEANUP_HEALTHY_LIFECYCLE_GRACE: Duration = Duration::from_secs(15);
const PACKAGE_DETERMINISTIC_CLEANUP_COORDINATOR_TERM_GRACE: Duration = Duration::from_secs(2);
const PACKAGE_DETERMINISTIC_CLEANUP_COORDINATOR_KILL_WAIT: Duration = Duration::from_secs(2);
const PACKAGE_DETERMINISTIC_CLEANUP_COMPLETION_PROOF_TIMEOUT: Duration = Duration::from_secs(5);
const PACKAGE_DETERMINISTIC_CLEANUP_GROUP_PROOF_TIMEOUT: Duration = Duration::from_secs(5);
const PACKAGE_DETERMINISTIC_CLEANUP_EXTERNAL_OBSERVATION_MARGIN: Duration = Duration::from_secs(5);
const PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER_ENV: &str =
    "CALCIFER_PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER";
const PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER_MODE: &str = "exit";
const PACKAGE_UNPROVEN_CLEANUP_CAUSAL_EXIT_HELPER_MODE: &str = "causal-exit";
const PACKAGE_UNPROVEN_CLEANUP_PARK_HELPER_MODE: &str = "park";
const PACKAGE_UNPROVEN_CLEANUP_PARK_READY: &str = "package-unproven-cleanup-park-ready";
const PACKAGE_UNPROVEN_CLEANUP_EXIT_CODE: u8 = 86;
const PACKAGE_UNPROVEN_CLEANUP_CHILD_TIMEOUT: Duration = Duration::from_secs(5);
const PACKAGE_UNPROVEN_CLEANUP_KILL_WAIT: Duration = Duration::from_secs(2);
const PACKAGE_UNPROVEN_CLEANUP_DIAGNOSTIC_LIMIT: u64 = 4 * 1024;

const PACKAGE_RECOVERY_CHECKPOINT_WIRE_NAMES: [(RecoveryCheckpoint, &str); 7] = [
    (RecoveryCheckpoint::StartupQueued, "startup-queued-v1"),
    (RecoveryCheckpoint::Ready, "ready-v1"),
    (RecoveryCheckpoint::Active, "active-v1"),
    (RecoveryCheckpoint::Suspended, "suspended-v1"),
    (
        RecoveryCheckpoint::RetainedQuiescing,
        "retained-quiescing-v1",
    ),
    (
        RecoveryCheckpoint::RetainedRestorePending,
        "retained-restore-pending-v1",
    ),
    (
        RecoveryCheckpoint::RetainedCleanupPending,
        "retained-cleanup-pending-v1",
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageProviderTarget {
    Official,
    DeterministicFixture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageStartupFault {
    TerminalChannelWriteRetainedStartupRestore,
}

#[derive(Default)]
struct PackageStartupTestSeams {
    launcher_override: Option<PathBuf>,
    startup_fault: Option<PackageStartupFault>,
}

impl PackageStartupTestSeams {
    fn deterministic(launcher: PathBuf, startup_fault: Option<PackageStartupFault>) -> Self {
        Self {
            launcher_override: Some(launcher),
            startup_fault,
        }
    }
}

/// Process-level projection for the package guardian helper.
///
/// The production coordinator cross-checks the terminal protocol frame against
/// the guardian process status. Letting libtest translate a deliberate failure
/// into its own harness exit code would invalidate that proof, so this decision
/// is intentionally independent of the selected provider target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageGuardianTerminalAction {
    ReturnSuccess,
    ExitCode(u8),
    EmulateSignal(u8),
}

const fn package_guardian_terminal_action(
    disposition: GuardianExitDisposition,
) -> PackageGuardianTerminalAction {
    match disposition {
        GuardianExitDisposition::Code(0) => PackageGuardianTerminalAction::ReturnSuccess,
        GuardianExitDisposition::Code(code) => PackageGuardianTerminalAction::ExitCode(code),
        GuardianExitDisposition::InternalFailure => PackageGuardianTerminalAction::ExitCode(1),
        GuardianExitDisposition::Signal(signal) => {
            PackageGuardianTerminalAction::EmulateSignal(signal)
        }
    }
}

fn apply_package_guardian_terminal_disposition(
    disposition: GuardianExitDisposition,
) -> Result<(), Box<dyn Error>> {
    match package_guardian_terminal_action(disposition) {
        PackageGuardianTerminalAction::ReturnSuccess => Ok(()),
        PackageGuardianTerminalAction::ExitCode(code) => std::process::exit(i32::from(code)),
        PackageGuardianTerminalAction::EmulateSignal(signal) => {
            // Reuse the production disposition projection. A successfully
            // emulated terminating signal does not return; any return is a
            // failed emulation and must fail closed with the protocol-defined
            // internal-failure status.
            let _ = GuardianRunOutcome::Terminal(GuardianExitDisposition::Signal(signal)).apply();
            std::process::exit(1)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageProviderTargetParseError;

impl fmt::Display for PackageProviderTargetParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package provider target was invalid")
    }
}

impl Error for PackageProviderTargetParseError {}

const fn package_provider_target_wire_name(target: PackageProviderTarget) -> &'static str {
    match target {
        PackageProviderTarget::Official => "official-v1",
        PackageProviderTarget::DeterministicFixture => "deterministic-fixture-v1",
    }
}

fn parse_package_provider_target(
    value: &OsStr,
) -> Result<PackageProviderTarget, PackageProviderTargetParseError> {
    match value.as_bytes() {
        b"official-v1" => Ok(PackageProviderTarget::Official),
        b"deterministic-fixture-v1" => Ok(PackageProviderTarget::DeterministicFixture),
        _ => Err(PackageProviderTargetParseError),
    }
}

fn package_provider_target_from_environment()
-> Result<PackageProviderTarget, PackageProviderTargetParseError> {
    std::env::var_os(PACKAGE_SUPERVISOR_PROVIDER_TARGET_ENV)
        .as_deref()
        .ok_or(PackageProviderTargetParseError)
        .and_then(parse_package_provider_target)
}

fn project_package_provider_target_environment(
    command: &mut Command,
    target: PackageProviderTarget,
) {
    command.env(
        PACKAGE_SUPERVISOR_PROVIDER_TARGET_ENV,
        package_provider_target_wire_name(target),
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageStartupFaultParseError;

impl fmt::Display for PackageStartupFaultParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package startup fault was invalid")
    }
}

impl Error for PackageStartupFaultParseError {}

const fn package_startup_fault_wire_name(fault: PackageStartupFault) -> &'static str {
    match fault {
        PackageStartupFault::TerminalChannelWriteRetainedStartupRestore => {
            "terminal-channel-write-retained-startup-restore-v1"
        }
    }
}

fn parse_package_startup_fault(
    value: &OsStr,
) -> Result<PackageStartupFault, PackageStartupFaultParseError> {
    match value.as_bytes() {
        b"terminal-channel-write-retained-startup-restore-v1" => {
            Ok(PackageStartupFault::TerminalChannelWriteRetainedStartupRestore)
        }
        _ => Err(PackageStartupFaultParseError),
    }
}

fn package_startup_fault_from_environment()
-> Result<Option<PackageStartupFault>, PackageStartupFaultParseError> {
    std::env::var_os(PACKAGE_SUPERVISOR_STARTUP_FAULT_ENV)
        .as_deref()
        .map(parse_package_startup_fault)
        .transpose()
}

fn project_package_startup_fault_environment(
    command: &mut Command,
    fault: Option<PackageStartupFault>,
) {
    if let Some(fault) = fault {
        command.env(
            PACKAGE_SUPERVISOR_STARTUP_FAULT_ENV,
            package_startup_fault_wire_name(fault),
        );
    }
}

fn validate_package_startup_fault_for_target(
    target: PackageProviderTarget,
    fault: Option<PackageStartupFault>,
) -> Result<Option<PackageStartupFault>, PackageStartupFaultParseError> {
    match (target, fault) {
        (PackageProviderTarget::DeterministicFixture, fault) => Ok(fault),
        (PackageProviderTarget::Official, None) => Ok(None),
        (PackageProviderTarget::Official, Some(_)) => Err(PackageStartupFaultParseError),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageCoordinatorReportProjection {
    FailedClean,
    CompletedClean,
}

impl PackageCoordinatorReportProjection {
    const fn for_checkpoint(checkpoint: RecoveryCheckpoint) -> Self {
        match checkpoint {
            RecoveryCheckpoint::StartupQueued
            | RecoveryCheckpoint::Ready
            | RecoveryCheckpoint::Active
            | RecoveryCheckpoint::Suspended => Self::FailedClean,
            RecoveryCheckpoint::RetainedQuiescing
            | RecoveryCheckpoint::RetainedRestorePending
            | RecoveryCheckpoint::RetainedCleanupPending => Self::CompletedClean,
        }
    }

    const fn selected(
        checkpoint: Option<RecoveryCheckpoint>,
        startup_fault: Option<PackageStartupFault>,
    ) -> Self {
        if startup_fault.is_some() {
            return Self::FailedClean;
        }
        match checkpoint {
            Some(checkpoint) => Self::for_checkpoint(checkpoint),
            None => Self::CompletedClean,
        }
    }

    const fn marker(self) -> &'static [u8] {
        match self {
            Self::FailedClean => b"failed-clean-v1\n",
            Self::CompletedClean => b"completed-clean-v1\n",
        }
    }

    fn require(
        self,
        guardian_status: std::process::ExitStatus,
        report: CoordinatorTerminalReport,
    ) -> Result<(), Box<dyn Error>> {
        let shared = report.worker == WorkerJoinStatus::JoinedClean
            && report.cleanup == CleanupStatus::Complete;
        let matches = match self {
            Self::FailedClean => {
                guardian_status.code() == Some(1)
                    && shared
                    && report.session == SessionStatus::Failed
                    && report.guardian_exit == GuardianExitDisposition::InternalFailure
            }
            Self::CompletedClean => {
                guardian_status.success()
                    && shared
                    && report.app
                        == (ChildDisposition::Exited {
                            code: 0,
                            stop_action: StopAction::Term,
                        })
                    && report.tui
                        == (ChildDisposition::Exited {
                            code: 0,
                            stop_action: StopAction::None,
                        })
                    && report.session == SessionStatus::Completed
                    && report.guardian_exit == GuardianExitDisposition::Code(0)
            }
        };
        if matches {
            Ok(())
        } else {
            Err("package production coordinator report projection did not match".into())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageRecoveryCheckpointParseError;

impl fmt::Display for PackageRecoveryCheckpointParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package recovery checkpoint was invalid")
    }
}

impl Error for PackageRecoveryCheckpointParseError {}

const fn package_recovery_checkpoint_wire_name(checkpoint: RecoveryCheckpoint) -> &'static str {
    match checkpoint {
        RecoveryCheckpoint::StartupQueued => "startup-queued-v1",
        RecoveryCheckpoint::Ready => "ready-v1",
        RecoveryCheckpoint::Active => "active-v1",
        RecoveryCheckpoint::Suspended => "suspended-v1",
        RecoveryCheckpoint::RetainedQuiescing => "retained-quiescing-v1",
        RecoveryCheckpoint::RetainedRestorePending => "retained-restore-pending-v1",
        RecoveryCheckpoint::RetainedCleanupPending => "retained-cleanup-pending-v1",
    }
}

const fn package_recovery_checkpoint_target_marker(checkpoint: RecoveryCheckpoint) -> &'static str {
    match checkpoint {
        RecoveryCheckpoint::StartupQueued => "recovery.target.startup-queued-v1",
        RecoveryCheckpoint::Ready => "recovery.target.ready-v1",
        RecoveryCheckpoint::Active => "recovery.target.active-v1",
        RecoveryCheckpoint::Suspended => "recovery.target.suspended-v1",
        RecoveryCheckpoint::RetainedQuiescing => "recovery.target.retained-quiescing-v1",
        RecoveryCheckpoint::RetainedRestorePending => "recovery.target.retained-restore-pending-v1",
        RecoveryCheckpoint::RetainedCleanupPending => "recovery.target.retained-cleanup-pending-v1",
    }
}

fn parse_package_recovery_checkpoint(
    value: &OsStr,
) -> Result<RecoveryCheckpoint, PackageRecoveryCheckpointParseError> {
    PACKAGE_RECOVERY_CHECKPOINT_WIRE_NAMES
        .iter()
        .find_map(|(checkpoint, wire_name)| (value == OsStr::new(wire_name)).then_some(*checkpoint))
        .ok_or(PackageRecoveryCheckpointParseError)
}

fn package_recovery_checkpoint_from_environment()
-> Result<Option<RecoveryCheckpoint>, PackageRecoveryCheckpointParseError> {
    std::env::var_os(PACKAGE_SUPERVISOR_RECOVERY_CHECKPOINT_ENV)
        .as_deref()
        .map(parse_package_recovery_checkpoint)
        .transpose()
}

fn project_package_recovery_checkpoint_environment(
    command: &mut Command,
    checkpoint: Option<RecoveryCheckpoint>,
) {
    if let Some(checkpoint) = checkpoint {
        command.env(
            PACKAGE_SUPERVISOR_RECOVERY_CHECKPOINT_ENV,
            package_recovery_checkpoint_wire_name(checkpoint),
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageRecoveryRequestState {
    Available,
    Consumed,
}

impl PackageRecoveryRequestState {
    fn begin_attempt(&mut self) -> bool {
        if *self == Self::Consumed {
            return false;
        }
        *self = Self::Consumed;
        true
    }
}

#[test]
fn package_recovery_checkpoint_wire_parser_is_closed_and_round_trips() {
    let cases = [
        (RecoveryCheckpoint::StartupQueued, "startup-queued-v1"),
        (RecoveryCheckpoint::Ready, "ready-v1"),
        (RecoveryCheckpoint::Active, "active-v1"),
        (RecoveryCheckpoint::Suspended, "suspended-v1"),
        (
            RecoveryCheckpoint::RetainedQuiescing,
            "retained-quiescing-v1",
        ),
        (
            RecoveryCheckpoint::RetainedRestorePending,
            "retained-restore-pending-v1",
        ),
        (
            RecoveryCheckpoint::RetainedCleanupPending,
            "retained-cleanup-pending-v1",
        ),
    ];
    for (checkpoint, wire_name) in cases {
        assert_eq!(package_recovery_checkpoint_wire_name(checkpoint), wire_name);
        assert_eq!(
            parse_package_recovery_checkpoint(OsStr::new(wire_name)),
            Ok(checkpoint)
        );
    }
    for invalid in [
        "",
        "active",
        "ACTIVE-V1",
        "retained-cleanup-pending-v2",
        "retained-cleanup-pending-v1 ",
        "startup-queued-v1\n",
    ] {
        assert_eq!(
            parse_package_recovery_checkpoint(OsStr::new(invalid)),
            Err(PackageRecoveryCheckpointParseError)
        );
    }
}

#[test]
fn package_recovery_checkpoint_target_markers_are_fixed_and_payload_free() {
    assert_eq!(
        PACKAGE_RECOVERY_CHECKPOINT_WIRE_NAMES
            .map(|(checkpoint, _)| package_recovery_checkpoint_target_marker(checkpoint)),
        [
            "recovery.target.startup-queued-v1",
            "recovery.target.ready-v1",
            "recovery.target.active-v1",
            "recovery.target.suspended-v1",
            "recovery.target.retained-quiescing-v1",
            "recovery.target.retained-restore-pending-v1",
            "recovery.target.retained-cleanup-pending-v1",
        ]
    );
    assert!(
        PACKAGE_RECOVERY_CHECKPOINT_WIRE_NAMES
            .iter()
            .all(|(checkpoint, _)| {
                let marker = package_recovery_checkpoint_target_marker(*checkpoint);
                marker.is_ascii()
                    && marker.starts_with("recovery.target.")
                    && !marker.contains('/')
                    && !marker.contains(' ')
            })
    );
}

#[test]
fn package_recovery_case_failure_markers_bind_trigger_and_checkpoint_without_payloads() {
    let mut markers = BTreeSet::new();
    for trigger in [
        PackageRecoveryTrigger::GenerationBoundRequest,
        PackageRecoveryTrigger::OwnerEof,
    ] {
        for (checkpoint, _) in PACKAGE_RECOVERY_CHECKPOINT_WIRE_NAMES {
            let marker = package_recovery_case_failure_marker(trigger, checkpoint);
            assert!(markers.insert(marker));
            assert!(marker.is_ascii());
            assert!(marker.starts_with("recovery.case-failed."));
            assert!(!marker.contains(['/', ' ', '\n', '\r']));
        }
    }
    assert_eq!(
        markers.len(),
        2 * PACKAGE_RECOVERY_CHECKPOINT_WIRE_NAMES.len()
    );
}

#[test]
fn package_recovery_checkpoint_environment_is_explicit_after_env_clear() {
    let mut selected = Command::new("package-helper");
    selected.env_clear();
    project_package_recovery_checkpoint_environment(
        &mut selected,
        Some(RecoveryCheckpoint::RetainedCleanupPending),
    );
    assert_eq!(
        selected
            .get_envs()
            .find(|(name, _)| *name == OsStr::new(PACKAGE_SUPERVISOR_RECOVERY_CHECKPOINT_ENV))
            .and_then(|(_, value)| value),
        Some(OsStr::new("retained-cleanup-pending-v1"))
    );

    let mut unselected = Command::new("package-helper");
    unselected.env_clear();
    project_package_recovery_checkpoint_environment(&mut unselected, None);
    assert!(
        unselected
            .get_envs()
            .all(|(name, _)| name != OsStr::new(PACKAGE_SUPERVISOR_RECOVERY_CHECKPOINT_ENV))
    );
}

#[test]
fn package_recovery_request_state_consumes_before_the_first_attempt() {
    let mut state = PackageRecoveryRequestState::Available;
    assert!(state.begin_attempt());
    assert_eq!(state, PackageRecoveryRequestState::Consumed);
    assert!(!state.begin_attempt());
}

#[test]
fn package_provider_target_wire_parser_is_closed_and_explicit_after_env_clear() {
    for (target, wire_name) in [
        (PackageProviderTarget::Official, "official-v1"),
        (
            PackageProviderTarget::DeterministicFixture,
            "deterministic-fixture-v1",
        ),
    ] {
        assert_eq!(package_provider_target_wire_name(target), wire_name);
        assert_eq!(
            parse_package_provider_target(OsStr::new(wire_name)),
            Ok(target)
        );
        let mut command = Command::new("package-helper");
        command.env_clear();
        project_package_provider_target_environment(&mut command, target);
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == OsStr::new(PACKAGE_SUPERVISOR_PROVIDER_TARGET_ENV))
                .and_then(|(_, value)| value),
            Some(OsStr::new(wire_name))
        );
    }
    for invalid in [
        "",
        "official",
        "OFFICIAL-V1",
        "deterministic-fixture-v2",
        "deterministic-fixture-v1\n",
        "arbitrary-v1",
    ] {
        assert!(parse_package_provider_target(OsStr::new(invalid)).is_err());
    }
}

#[test]
fn package_startup_fault_is_closed_explicit_and_fixture_only() {
    let fault = PackageStartupFault::TerminalChannelWriteRetainedStartupRestore;
    let wire_name = "terminal-channel-write-retained-startup-restore-v1";
    assert_eq!(package_startup_fault_wire_name(fault), wire_name);
    assert_eq!(
        parse_package_startup_fault(OsStr::new(wire_name)),
        Ok(fault)
    );
    for invalid in [
        "",
        "terminal-channel-write",
        "terminal-channel-write-retained-startup-restore-v2",
        "terminal-channel-write-retained-startup-restore-v1\n",
        "arbitrary-v1",
    ] {
        assert_eq!(
            parse_package_startup_fault(OsStr::new(invalid)),
            Err(PackageStartupFaultParseError)
        );
    }
    assert_eq!(
        validate_package_startup_fault_for_target(
            PackageProviderTarget::DeterministicFixture,
            Some(fault),
        ),
        Ok(Some(fault))
    );
    assert_eq!(
        validate_package_startup_fault_for_target(PackageProviderTarget::Official, Some(fault)),
        Err(PackageStartupFaultParseError)
    );

    let mut selected = Command::new("package-helper");
    selected.env_clear();
    project_package_startup_fault_environment(&mut selected, Some(fault));
    assert_eq!(
        selected
            .get_envs()
            .find(|(name, _)| *name == OsStr::new(PACKAGE_SUPERVISOR_STARTUP_FAULT_ENV))
            .and_then(|(_, value)| value),
        Some(OsStr::new(wire_name))
    );
    let mut unselected = Command::new("package-helper");
    unselected.env_clear();
    project_package_startup_fault_environment(&mut unselected, None);
    assert!(
        unselected
            .get_envs()
            .all(|(name, _)| name != OsStr::new(PACKAGE_SUPERVISOR_STARTUP_FAULT_ENV))
    );
}

#[test]
fn package_guardian_build_cleanup_timeout_is_provider_target_aware() {
    let official = package_guardian_bounds(PackageProviderTarget::Official);
    let deterministic = package_guardian_bounds(PackageProviderTarget::DeterministicFixture);

    assert_eq!(
        official.build_cleanup_timeout,
        PACKAGE_SUPERVISOR_COMPATIBILITY_TIMEOUT
    );
    assert_eq!(official.startup_timeout, PACKAGE_SUPERVISOR_STARTUP_TIMEOUT);
    assert_eq!(
        official.compatibility_timeout,
        PACKAGE_SUPERVISOR_COMPATIBILITY_TIMEOUT
    );
    assert_eq!(official.relay_start_timeout, Duration::from_secs(15));
    assert!(official.build_cleanup_timeout >= Duration::from_secs(180));
    assert_eq!(
        deterministic.startup_timeout,
        PACKAGE_DETERMINISTIC_SUPERVISOR_TIMEOUT
    );
    assert_eq!(
        deterministic.startup_timeout,
        Duration::from_secs(45),
        "the deterministic fixture keeps a full 30-second relay window after pre-relay work"
    );
    assert_eq!(
        deterministic.compatibility_timeout,
        PACKAGE_DETERMINISTIC_SUPERVISOR_TIMEOUT
    );
    assert_eq!(deterministic.relay_start_timeout, Duration::from_secs(30));
    assert_eq!(deterministic.build_cleanup_timeout, Duration::from_secs(10));
    let deterministic_minimum_startup = PACKAGE_DETERMINISTIC_PRE_RELAY_STARTUP_RESERVE
        .checked_add(deterministic.relay_start_timeout);
    assert!(
        deterministic_minimum_startup
            .is_some_and(|minimum| deterministic.startup_timeout >= minimum),
        "the deterministic startup fence must reserve pre-relay work plus one relay phase"
    );
}

#[test]
fn deterministic_suite_budget_reserves_a_full_generation_and_refunds_only_unused_time()
-> Result<(), Box<dyn Error>> {
    let mut budget = PackageDeterministicSuiteBudget::new(Duration::from_secs(300));
    let first = budget
        .try_reserve(Duration::from_secs(105))
        .ok_or("the first deterministic generation did not fit")?;
    let second = budget
        .try_reserve(Duration::from_secs(105))
        .ok_or("the second deterministic generation did not fit")?;

    assert_eq!(budget.available(), Duration::from_secs(90));
    assert!(
        budget.try_reserve(Duration::from_secs(105)).is_none(),
        "an unbacked generation must be rejected before it starts"
    );
    assert_eq!(budget.available(), Duration::from_secs(90));

    budget.settle(first, Duration::from_secs(10));
    assert_eq!(budget.available(), Duration::from_secs(185));
    budget.settle(second, Duration::from_secs(105));
    assert_eq!(budget.available(), Duration::from_secs(185));
    Ok(())
}

#[test]
fn deterministic_suite_budget_debits_a_generation_overrun() -> Result<(), Box<dyn Error>> {
    let mut budget = PackageDeterministicSuiteBudget::new(Duration::from_secs(300));
    let reservation = budget
        .try_reserve(Duration::from_secs(105))
        .ok_or("the deterministic generation did not fit")?;

    budget.settle(reservation, Duration::from_secs(106));

    assert_eq!(budget.available(), Duration::from_secs(194));
    Ok(())
}

#[test]
fn deterministic_suite_budget_covers_at_least_one_complete_generation_fence() {
    assert_eq!(
        PACKAGE_DETERMINISTIC_SUITE_TIMEOUT,
        Duration::from_secs(360)
    );
    assert!(PACKAGE_DETERMINISTIC_SUITE_TIMEOUT >= PACKAGE_DETERMINISTIC_EXTERNAL_HARD_TIMEOUT);
}

#[test]
fn package_guardian_helper_preserves_every_terminal_disposition_exactly() {
    assert_eq!(
        package_guardian_terminal_action(GuardianExitDisposition::Code(0)),
        PackageGuardianTerminalAction::ReturnSuccess
    );
    assert_eq!(
        package_guardian_terminal_action(GuardianExitDisposition::Code(23)),
        PackageGuardianTerminalAction::ExitCode(23)
    );
    assert_eq!(
        package_guardian_terminal_action(GuardianExitDisposition::InternalFailure),
        PackageGuardianTerminalAction::ExitCode(1)
    );
    assert_eq!(
        package_guardian_terminal_action(GuardianExitDisposition::Signal(15)),
        PackageGuardianTerminalAction::EmulateSignal(15)
    );
}

#[test]
fn package_coordinator_report_projection_is_exhaustive_over_recovery_checkpoints() {
    for (checkpoint, projection, marker) in [
        (
            RecoveryCheckpoint::StartupQueued,
            PackageCoordinatorReportProjection::FailedClean,
            b"failed-clean-v1\n".as_slice(),
        ),
        (
            RecoveryCheckpoint::Ready,
            PackageCoordinatorReportProjection::FailedClean,
            b"failed-clean-v1\n".as_slice(),
        ),
        (
            RecoveryCheckpoint::Active,
            PackageCoordinatorReportProjection::FailedClean,
            b"failed-clean-v1\n".as_slice(),
        ),
        (
            RecoveryCheckpoint::Suspended,
            PackageCoordinatorReportProjection::FailedClean,
            b"failed-clean-v1\n".as_slice(),
        ),
        (
            RecoveryCheckpoint::RetainedQuiescing,
            PackageCoordinatorReportProjection::CompletedClean,
            b"completed-clean-v1\n".as_slice(),
        ),
        (
            RecoveryCheckpoint::RetainedRestorePending,
            PackageCoordinatorReportProjection::CompletedClean,
            b"completed-clean-v1\n".as_slice(),
        ),
        (
            RecoveryCheckpoint::RetainedCleanupPending,
            PackageCoordinatorReportProjection::CompletedClean,
            b"completed-clean-v1\n".as_slice(),
        ),
    ] {
        assert_eq!(
            PackageCoordinatorReportProjection::for_checkpoint(checkpoint),
            projection
        );
        assert_eq!(projection.marker(), marker);
    }
    assert_eq!(
        PackageCoordinatorReportProjection::selected(
            Some(RecoveryCheckpoint::RetainedRestorePending),
            Some(PackageStartupFault::TerminalChannelWriteRetainedStartupRestore),
        ),
        PackageCoordinatorReportProjection::FailedClean,
        "a retained startup failure inherited the healthy-session completion projection"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageExercisePhase {
    ChildrenValidated,
    InitialGateObserved,
    RawModeObserved,
    PostGateTuiLive,
    PreReadyInputBlocked,
    StartupSentinelObserved,
    InitialInputWritten,
    InitialInputObserved,
    ResizeObserved,
    SuspendObserved,
    StoppedStateValidated,
    SuspendedInputBlocked,
    ResumeObserved,
    ResumeGateObserved,
    ResumeRawModeObserved,
    ResumeGroupValidated,
    BackendInferenceCompleted,
    ResponseSentinelObserved,
    ExitInputWritten,
    ExitInputObserved,
    CoordinatorExited,
    CompletionVerified,
    SessionObservationVerified,
    OutputDrainVerified,
    TerminalRestored,
}

impl PackageExercisePhase {
    const fn marker(self) -> &'static str {
        match self {
            Self::ChildrenValidated => "exercise.children-validated",
            Self::InitialGateObserved => "exercise.initial-gate-observed",
            Self::RawModeObserved => "exercise.raw-mode-observed",
            Self::PostGateTuiLive => "exercise.post-gate-tui-live",
            Self::PreReadyInputBlocked => "exercise.pre-ready-input-blocked",
            Self::StartupSentinelObserved => "exercise.tui-startup-sentinel-observed",
            Self::InitialInputWritten => "exercise.initial-input-written",
            Self::InitialInputObserved => "exercise.initial-input-observed",
            Self::ResizeObserved => "exercise.resize-observed",
            Self::SuspendObserved => "exercise.suspend-observed",
            Self::StoppedStateValidated => "exercise.stopped-state-validated",
            Self::SuspendedInputBlocked => "exercise.suspended-input-blocked",
            Self::ResumeObserved => "exercise.resume-observed",
            Self::ResumeGateObserved => "exercise.resume-gate-observed",
            Self::ResumeRawModeObserved => "exercise.resume-raw-mode-observed",
            Self::ResumeGroupValidated => "exercise.resume-group-validated",
            Self::BackendInferenceCompleted => "exercise.backend-inference-completed",
            Self::ResponseSentinelObserved => "exercise.tui-response-sentinel-observed",
            Self::ExitInputWritten => "exercise.exit-input-written",
            Self::ExitInputObserved => "exercise.exit-input-observed",
            Self::CoordinatorExited => "exercise.coordinator-exited",
            Self::CompletionVerified => "exercise.completion-verified",
            Self::SessionObservationVerified => "exercise.session-observation-verified",
            Self::OutputDrainVerified => "exercise.output-drain-verified",
            Self::TerminalRestored => "exercise.terminal-restored",
        }
    }
}

const PACKAGE_EXERCISE_PHASES: [PackageExercisePhase; 25] = [
    PackageExercisePhase::ChildrenValidated,
    PackageExercisePhase::InitialGateObserved,
    PackageExercisePhase::RawModeObserved,
    PackageExercisePhase::PostGateTuiLive,
    PackageExercisePhase::PreReadyInputBlocked,
    PackageExercisePhase::StartupSentinelObserved,
    PackageExercisePhase::InitialInputWritten,
    PackageExercisePhase::InitialInputObserved,
    PackageExercisePhase::BackendInferenceCompleted,
    PackageExercisePhase::ResponseSentinelObserved,
    PackageExercisePhase::ResizeObserved,
    PackageExercisePhase::SuspendObserved,
    PackageExercisePhase::StoppedStateValidated,
    PackageExercisePhase::SuspendedInputBlocked,
    PackageExercisePhase::ResumeObserved,
    PackageExercisePhase::ResumeGateObserved,
    PackageExercisePhase::ResumeRawModeObserved,
    PackageExercisePhase::ResumeGroupValidated,
    PackageExercisePhase::ExitInputWritten,
    PackageExercisePhase::ExitInputObserved,
    PackageExercisePhase::CoordinatorExited,
    PackageExercisePhase::CompletionVerified,
    PackageExercisePhase::SessionObservationVerified,
    PackageExercisePhase::OutputDrainVerified,
    PackageExercisePhase::TerminalRestored,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageRecoveryVerificationPhase {
    CheckpointDriven,
    CheckpointVerified,
    ObservationOnlyVerified,
    RequestSent,
    OwnerWriteShutdown,
    OneShotVerified,
    CoordinatorExited,
    ReportVerified,
    CompletionVerified,
    TuiGroupAbsent,
    AppGroupAbsent,
    GuardianGroupAbsent,
    ReportedGroupsAbsent,
    RuntimeEmpty,
}

impl PackageRecoveryVerificationPhase {
    const fn marker(self) -> &'static str {
        match self {
            Self::CheckpointDriven => "recovery.checkpoint-driven",
            Self::CheckpointVerified => "recovery.checkpoint-verified",
            Self::ObservationOnlyVerified => "recovery.observation-only-verified",
            Self::RequestSent => "recovery.request-sent",
            Self::OwnerWriteShutdown => "recovery.owner-write-shutdown",
            Self::OneShotVerified => "recovery.one-shot-verified",
            Self::CoordinatorExited => "recovery.coordinator-exited",
            Self::ReportVerified => "recovery.report-verified",
            Self::CompletionVerified => "recovery.completion-verified",
            Self::TuiGroupAbsent => "recovery.tui-group-absent",
            Self::AppGroupAbsent => "recovery.app-group-absent",
            Self::GuardianGroupAbsent => "recovery.guardian-group-absent",
            Self::ReportedGroupsAbsent => "recovery.reported-groups-absent",
            Self::RuntimeEmpty => "recovery.runtime-empty",
        }
    }
}

const PACKAGE_RECOVERY_VERIFICATION_PHASES: [PackageRecoveryVerificationPhase; 14] = [
    PackageRecoveryVerificationPhase::CheckpointDriven,
    PackageRecoveryVerificationPhase::CheckpointVerified,
    PackageRecoveryVerificationPhase::ObservationOnlyVerified,
    PackageRecoveryVerificationPhase::RequestSent,
    PackageRecoveryVerificationPhase::OwnerWriteShutdown,
    PackageRecoveryVerificationPhase::OneShotVerified,
    PackageRecoveryVerificationPhase::CoordinatorExited,
    PackageRecoveryVerificationPhase::ReportVerified,
    PackageRecoveryVerificationPhase::CompletionVerified,
    PackageRecoveryVerificationPhase::TuiGroupAbsent,
    PackageRecoveryVerificationPhase::AppGroupAbsent,
    PackageRecoveryVerificationPhase::GuardianGroupAbsent,
    PackageRecoveryVerificationPhase::ReportedGroupsAbsent,
    PackageRecoveryVerificationPhase::RuntimeEmpty,
];

const PACKAGE_RECOVERY_DRIVE_FAILURE_MARKERS: [&str; 9] = [
    "recovery.drive-failed.initial-gate",
    "recovery.drive-failed.raw-mode",
    "recovery.drive-failed.startup-sentinel",
    "recovery.drive-failed.initial-input-write",
    "recovery.drive-failed.initial-input-observation",
    "recovery.drive-failed.inference",
    "recovery.drive-failed.response-sentinel",
    "recovery.drive-failed.exit-input-write",
    "recovery.drive-failed.exit-input-observation",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageRecoveryDriveFailure {
    InitialGate,
    RawMode,
    StartupSentinel,
    InitialInputWrite,
    InitialInputObservation,
    Inference,
    ResponseSentinel,
    ExitInputWrite,
    ExitInputObservation,
}

impl PackageRecoveryDriveFailure {
    const fn marker(self) -> &'static str {
        match self {
            Self::InitialGate => "recovery.drive-failed.initial-gate",
            Self::RawMode => "recovery.drive-failed.raw-mode",
            Self::StartupSentinel => "recovery.drive-failed.startup-sentinel",
            Self::InitialInputWrite => "recovery.drive-failed.initial-input-write",
            Self::InitialInputObservation => "recovery.drive-failed.initial-input-observation",
            Self::Inference => "recovery.drive-failed.inference",
            Self::ResponseSentinel => "recovery.drive-failed.response-sentinel",
            Self::ExitInputWrite => "recovery.drive-failed.exit-input-write",
            Self::ExitInputObservation => "recovery.drive-failed.exit-input-observation",
        }
    }
}

impl fmt::Display for PackageRecoveryDriveFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package retained-recovery drive failed")
    }
}

impl Error for PackageRecoveryDriveFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedPackageStartupFailure(&'static str);

impl FixedPackageStartupFailure {
    fn from_marker(marker: &str) -> Option<Self> {
        fixed_package_startup_failure_marker(marker).map(Self)
    }

    const fn marker(self) -> &'static str {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageRecoveryStartupDriveFailure {
    startup: FixedPackageStartupFailure,
    drive: PackageRecoveryDriveFailure,
}

impl PackageRecoveryStartupDriveFailure {
    const fn new(startup: FixedPackageStartupFailure, drive: PackageRecoveryDriveFailure) -> Self {
        Self { startup, drive }
    }
}

impl fmt::Display for PackageRecoveryStartupDriveFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a fixed package startup failure ended the retained-recovery drive")
    }
}

impl Error for PackageRecoveryStartupDriveFailure {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PackageRecoveryFailureEvidence {
    primary: Option<PackageRecoveryDriveFailure>,
    drive_context: Option<PackageRecoveryDriveFailure>,
    secondary: Option<&'static str>,
}

impl PackageRecoveryFailureEvidence {
    fn snapshot_error(&mut self, error: &(dyn Error + 'static)) {
        if let Some(failure) = error.downcast_ref::<PackageRecoveryStartupDriveFailure>() {
            self.primary.get_or_insert(failure.drive);
            self.drive_context.get_or_insert(failure.drive);
            self.snapshot_secondary(Some(failure.startup.marker()));
        } else if let Some(failure) = error.downcast_ref::<PackageRecoveryDriveFailure>() {
            self.primary.get_or_insert(*failure);
            self.drive_context.get_or_insert(*failure);
        }
    }

    fn snapshot_secondary(&mut self, candidate: Option<&'static str>) {
        let Some(candidate) = candidate else {
            return;
        };
        if self.primary.is_none()
            || self.primary_marker() == Some(candidate)
            || self.drive_context.map(PackageRecoveryDriveFailure::marker) == Some(candidate)
        {
            return;
        }
        self.secondary.get_or_insert(candidate);
    }

    const fn primary_marker(self) -> Option<&'static str> {
        match self.primary {
            Some(failure) => Some(failure.marker()),
            None => None,
        }
    }

    const fn drive_context(self) -> Option<PackageRecoveryDriveFailure> {
        self.drive_context
    }

    const fn secondary_marker(self) -> Option<&'static str> {
        self.secondary
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageInitialGateObservation {
    Opened,
    StartupFailure(FixedPackageStartupFailure),
}

const PACKAGE_RECOVERY_OBSERVATION_FAILURE_MARKERS: [&str; 2] = [
    "recovery.observation-only-failed.coordinator-wait",
    "recovery.observation-only-failed.coordinator-exited",
];

const PACKAGE_SESSION_BACKEND_FAILURE_MARKERS: &[&str] = &[
    "package-backend.lifecycle.nonblocking",
    "package-backend.lifecycle.cancel-disconnected",
    "package-backend.lifecycle.deadline",
    "package-backend.listener.accept",
    "package-backend.listener.request-limit",
    "package-backend.stream.blocking",
    "package-backend.stream.read-timeout",
    "package-backend.stream.write-timeout",
    "package-backend.request.read",
    "package-backend.request.eof",
    "package-backend.request.size",
    "package-backend.request.headers",
    "package-backend.request.line",
    "package-backend.request.header-malformed",
    "package-backend.request.authorization-duplicate",
    "package-backend.request.account-duplicate",
    "package-backend.request.content-length-duplicate",
    "package-backend.request.content-type-duplicate",
    "package-backend.request.accept-duplicate",
    "package-backend.request.credentials",
    "package-backend.models.body",
    "package-backend.response.invalid-json",
    "package-backend.response.model",
    "package-backend.response.stream",
    "package-backend.response.prompt-missing",
    "package-backend.response.prompt-duplicate",
    "package-backend.response.media",
    "package-backend.response.credentials",
    "package-backend.response.encoding",
    "package-backend.response.content-length",
    "package-backend.response.trailing",
    "package-backend.response.length-overflow",
    "package-backend.response.body-eof",
    "package-backend.response.usage-serialization",
    "package-backend.response.reset-serialization",
    "package-backend.response.json-write",
    "package-backend.response.sse-write",
    "package-backend.response.sse-eof",
    "package-backend.response.disconnect",
    "package-backend.observation.duplicate-responses",
    "package-backend.observation.completion-publish",
    "package-backend.unclassified",
];
const PACKAGE_NETWORK_FAILURE_MARKERS: &[&str] = &[
    "package-network.authority",
    "package-network.registry-read",
    "package-network.registry-shape",
    "package-network.profile-identity",
    "package-network.profile-target",
    "package-network.profile-home",
    "package-network.config-read",
    "package-network.config-contract",
    "package-network.evidence-root",
    "package-network.evidence-entry",
    "package-network.evidence-file",
    "package-network.evidence-bound",
    "package-network.evidence-reference.chatgpt",
    "package-network.evidence-reference.auth-openai",
    "package-network.evidence-reference.api-openai",
    "package-network.evidence-missing",
];
const PACKAGE_JOB_CONTROL_FAILURE_MARKERS: [&str; 8] = [
    "exercise.job-control-failed.tui-stop-wait",
    "exercise.job-control-failed.tui-stopped-snapshot",
    "exercise.job-control-failed.coordinator-stop-wait",
    "exercise.job-control-failed.stopped-termios-read",
    "exercise.job-control-failed.stopped-termios-snapshot-missing",
    "exercise.job-control-failed.stopped-termios-mismatch",
    "exercise.job-control-failed.resume-apply",
    "exercise.job-control-failed.resume-rearm",
];
const PACKAGE_SESSION_OBSERVATION_FAILURE_MARKERS: [&str; 16] = [
    "exercise.session-observation.observer-unclassified",
    "exercise.session-observation.observer-marker-write",
    "exercise.session-observation.observer-output-order",
    "exercise.session-observation.observer-initial-size",
    "exercise.session-observation.observer-input-order",
    "exercise.session-observation.observer-input-length-overflow",
    "exercise.session-observation.observer-input-limit",
    "exercise.session-observation.observer-input-persist",
    "exercise.session-observation.observer-duplicate-shutdown",
    "exercise.session-observation.output",
    "exercise.session-observation.initial-size",
    "exercise.session-observation.resize",
    "exercise.session-observation.resume",
    "exercise.session-observation.suspend",
    "exercise.session-observation.input",
    "exercise.session-observation.terminal",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageSessionObservationFailure {
    ObserverUnclassified,
    ObserverMarkerWrite,
    ObserverOutputOrder,
    ObserverInitialSize,
    ObserverInputOrder,
    ObserverInputLengthOverflow,
    ObserverInputLimit,
    ObserverInputPersist,
    ObserverDuplicateShutdown,
    Output,
    InitialSize,
    Resize,
    Resume,
    Suspend,
    Input,
    Terminal,
}

impl PackageSessionObservationFailure {
    const fn marker(self) -> &'static str {
        match self {
            Self::ObserverUnclassified => "exercise.session-observation.observer-unclassified",
            Self::ObserverMarkerWrite => "exercise.session-observation.observer-marker-write",
            Self::ObserverOutputOrder => "exercise.session-observation.observer-output-order",
            Self::ObserverInitialSize => "exercise.session-observation.observer-initial-size",
            Self::ObserverInputOrder => "exercise.session-observation.observer-input-order",
            Self::ObserverInputLengthOverflow => {
                "exercise.session-observation.observer-input-length-overflow"
            }
            Self::ObserverInputLimit => "exercise.session-observation.observer-input-limit",
            Self::ObserverInputPersist => "exercise.session-observation.observer-input-persist",
            Self::ObserverDuplicateShutdown => {
                "exercise.session-observation.observer-duplicate-shutdown"
            }
            Self::Output => "exercise.session-observation.output",
            Self::InitialSize => "exercise.session-observation.initial-size",
            Self::Resize => "exercise.session-observation.resize",
            Self::Resume => "exercise.session-observation.resume",
            Self::Suspend => "exercise.session-observation.suspend",
            Self::Input => "exercise.session-observation.input",
            Self::Terminal => "exercise.session-observation.terminal",
        }
    }
}

impl fmt::Display for PackageSessionObservationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("package session observation failed")
    }
}

impl Error for PackageSessionObservationFailure {}

fn validate_package_session_observation(
    observation: &PackagedSessionObservation,
    expected_input: &[u8],
) -> Result<(), PackageSessionObservationFailure> {
    if observation.observation_failed || observation.integrity_failure.is_some() {
        return Err(match observation.integrity_failure {
            None => PackageSessionObservationFailure::ObserverUnclassified,
            Some(PackagedObservationIntegrityFailure::MarkerWrite) => {
                PackageSessionObservationFailure::ObserverMarkerWrite
            }
            Some(PackagedObservationIntegrityFailure::OutputOrder) => {
                PackageSessionObservationFailure::ObserverOutputOrder
            }
            Some(PackagedObservationIntegrityFailure::InitialSize) => {
                PackageSessionObservationFailure::ObserverInitialSize
            }
            Some(PackagedObservationIntegrityFailure::InputOrder) => {
                PackageSessionObservationFailure::ObserverInputOrder
            }
            Some(PackagedObservationIntegrityFailure::InputLengthOverflow) => {
                PackageSessionObservationFailure::ObserverInputLengthOverflow
            }
            Some(PackagedObservationIntegrityFailure::InputLimit) => {
                PackageSessionObservationFailure::ObserverInputLimit
            }
            Some(PackagedObservationIntegrityFailure::InputPersist) => {
                PackageSessionObservationFailure::ObserverInputPersist
            }
            Some(PackagedObservationIntegrityFailure::DuplicateShutdown) => {
                PackageSessionObservationFailure::ObserverDuplicateShutdown
            }
        });
    }
    if !observation.output_sentinel_seen {
        return Err(PackageSessionObservationFailure::Output);
    }
    if observation.initial_size != Some((37, 111)) {
        return Err(PackageSessionObservationFailure::InitialSize);
    }
    if observation.resized_sizes != [(41, 123)] {
        return Err(PackageSessionObservationFailure::Resize);
    }
    if observation.resumed_sizes != [(43, 125)] {
        return Err(PackageSessionObservationFailure::Resume);
    }
    if observation.suspend_count != 1 {
        return Err(PackageSessionObservationFailure::Suspend);
    }
    if observation.input != expected_input {
        return Err(PackageSessionObservationFailure::Input);
    }
    if !observation.shutdown_observed
        || observation.termination_cause != Some(PackagedObservedTerminationCause::NaturalTuiEof)
        || observation.operation_error != Some(PackagedObservedOperationError::None)
        || observation.tui_disposition != Some(PackagedObservedTuiDisposition::ExitZero)
        || observation.worker_join != Some(PackagedObservedWorkerJoin::JoinedClean)
        || observation.cleanup_clean != Some(true)
        || observation.session_status != Some(PackagedObservedSessionStatus::Completed)
        || observation.guardian_exit != Some(PackagedObservedGuardianExit::Success)
    {
        return Err(PackageSessionObservationFailure::Terminal);
    }
    Ok(())
}

fn record_package_exercise_phase(report: &Path, phase: PackageExercisePhase) {
    let _ = write_private_new(report.join(phase.marker()).as_path(), b"reached\n");
}

fn record_package_recovery_verification_phase(
    report: &Path,
    phase: PackageRecoveryVerificationPhase,
) {
    let _ = write_private_new(report.join(phase.marker()).as_path(), b"reached\n");
}

const fn package_checkpoint_wait_failure_marker(error: CompletionError) -> &'static str {
    match error {
        CompletionError::Create => "recovery.checkpoint-failed.create",
        CompletionError::Descriptor => "recovery.checkpoint-failed.descriptor",
        CompletionError::Inherited => "recovery.checkpoint-failed.inherited",
        CompletionError::Io => "recovery.checkpoint-failed.io",
        CompletionError::MissingFrame => "recovery.checkpoint-failed.missing-frame",
        CompletionError::InvalidFrame => "recovery.checkpoint-failed.invalid-frame",
        CompletionError::TrailingData => "recovery.checkpoint-failed.trailing-data",
        CompletionError::RecoveryDeadline => "recovery.checkpoint-failed.deadline",
        CompletionError::RecoveryPeerExited => "recovery.checkpoint-failed.peer-exited",
        CompletionError::RecoveryReplay => "recovery.checkpoint-failed.replay",
        CompletionError::RecoveryTooLate => "recovery.checkpoint-failed.too-late",
    }
}

fn record_package_diagnostic_marker(report: &Path, marker: &'static str) {
    let _ = write_private_new(report.join(marker).as_path(), b"classified\n");
}

fn classify_package_recovery_drive_stage<T, E>(
    report: &Path,
    failure: PackageRecoveryDriveFailure,
    result: Result<T, E>,
) -> Result<T, Box<dyn Error>> {
    debug_assert!(PACKAGE_RECOVERY_DRIVE_FAILURE_MARKERS.contains(&failure.marker()));
    match result {
        Ok(value) => Ok(value),
        Err(_) => {
            record_package_diagnostic_marker(report, failure.marker());
            Err(Box::new(failure))
        }
    }
}

fn classify_package_recovery_initial_gate(
    report: &Path,
    result: Result<PackageInitialGateObservation, Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    match result {
        Ok(PackageInitialGateObservation::Opened) => Ok(()),
        Ok(PackageInitialGateObservation::StartupFailure(failure)) => {
            let drive = PackageRecoveryDriveFailure::InitialGate;
            record_package_diagnostic_marker(report, drive.marker());
            Err(Box::new(PackageRecoveryStartupDriveFailure::new(
                failure, drive,
            )))
        }
        Err(_) => {
            let failure = PackageRecoveryDriveFailure::InitialGate;
            record_package_diagnostic_marker(report, failure.marker());
            Err(Box::new(failure))
        }
    }
}

fn activate_selected_recovery_after_drive<Activate>(
    drive_result: Result<(), Box<dyn Error>>,
    checkpoint_result: Result<(), CompletionError>,
    observation_result: Option<Result<(), Box<dyn Error>>>,
    activate: Activate,
) -> Result<(), Box<dyn Error>>
where
    Activate: FnOnce() -> Result<(), Box<dyn Error>>,
{
    let activation_result = activate();
    drive_result?;
    if let Err(error) = checkpoint_result {
        return Err(error.into());
    }
    if let Some(Err(error)) = observation_result {
        return Err(error);
    }
    activation_result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageRecoveryObservationFailure {
    CoordinatorWait,
    CoordinatorExited,
}

impl PackageRecoveryObservationFailure {
    const fn marker(self) -> &'static str {
        match self {
            Self::CoordinatorWait => "recovery.observation-only-failed.coordinator-wait",
            Self::CoordinatorExited => "recovery.observation-only-failed.coordinator-exited",
        }
    }
}

impl fmt::Display for PackageRecoveryObservationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package observation-only proof failed")
    }
}

impl Error for PackageRecoveryObservationFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageJobControlFailure {
    TuiStopWait,
    TuiStoppedSnapshot(PackageProcessSnapshotError),
    CoordinatorStopWait,
    StoppedTermiosRead,
    StoppedTermiosSnapshotMissing,
    StoppedTermiosMismatch,
    ResumeApply,
    ResumeRearm,
}

impl PackageJobControlFailure {
    const fn marker(self) -> &'static str {
        match self {
            Self::TuiStopWait => "exercise.job-control-failed.tui-stop-wait",
            Self::TuiStoppedSnapshot(_) => "exercise.job-control-failed.tui-stopped-snapshot",
            Self::CoordinatorStopWait => "exercise.job-control-failed.coordinator-stop-wait",
            Self::StoppedTermiosRead => "exercise.job-control-failed.stopped-termios-read",
            Self::StoppedTermiosSnapshotMissing => {
                "exercise.job-control-failed.stopped-termios-snapshot-missing"
            }
            Self::StoppedTermiosMismatch => "exercise.job-control-failed.stopped-termios-mismatch",
            Self::ResumeApply => "exercise.job-control-failed.resume-apply",
            Self::ResumeRearm => "exercise.job-control-failed.resume-rearm",
        }
    }
}

impl fmt::Display for PackageJobControlFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package job-control proof failed")
    }
}

impl Error for PackageJobControlFailure {}

fn classify_package_job_control_stage<T, E>(
    report: &Path,
    failure: PackageJobControlFailure,
    result: Result<T, E>,
) -> Result<T, Box<dyn Error>> {
    match result {
        Ok(value) => Ok(value),
        Err(_) => {
            record_package_diagnostic_marker(report, failure.marker());
            Err(Box::new(failure))
        }
    }
}

#[test]
fn package_job_control_failures_are_closed_fixed_and_payload_free() {
    let variants = [
        PackageJobControlFailure::TuiStopWait,
        PackageJobControlFailure::TuiStoppedSnapshot(PackageProcessSnapshotError::Identity),
        PackageJobControlFailure::CoordinatorStopWait,
        PackageJobControlFailure::StoppedTermiosRead,
        PackageJobControlFailure::StoppedTermiosSnapshotMissing,
        PackageJobControlFailure::StoppedTermiosMismatch,
        PackageJobControlFailure::ResumeApply,
        PackageJobControlFailure::ResumeRearm,
    ];
    assert_eq!(
        variants.map(PackageJobControlFailure::marker),
        PACKAGE_JOB_CONTROL_FAILURE_MARKERS
    );
    let markers: BTreeSet<_> = variants
        .iter()
        .copied()
        .map(PackageJobControlFailure::marker)
        .collect();
    assert_eq!(markers.len(), variants.len());
    assert!(markers.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("exercise.job-control-failed.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
    assert!(variants.iter().all(|failure| {
        failure.to_string() == "the package job-control proof failed"
            && !format!("{failure:?}").contains("private")
    }));
}

#[test]
fn package_job_control_classifier_records_only_a_closed_failure() -> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let failure = PackageJobControlFailure::ResumeApply;

    classify_package_job_control_stage(&report, failure, Ok::<_, &str>(()))?;
    assert!(!report.join(failure.marker()).exists());
    let error = require_rejected_test_result(
        classify_package_job_control_stage::<(), _>(
            &report,
            failure,
            Err("private resume credential and terminal detail"),
        ),
        "a failed job-control stage was accepted",
    )?;
    assert_eq!(error.to_string(), "the package job-control proof failed");
    assert!(!format!("{error:?}").contains("private resume"));
    assert_eq!(
        read_private_bounded(&report.join(failure.marker()), 64)?,
        b"classified\n"
    );
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_job_control_catalog()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let terminal_marker = PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0];
    write_private_new(&report.join(terminal_marker), b"classified\n")?;

    for marker in PACKAGE_JOB_CONTROL_FAILURE_MARKERS {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker),
            "an outer job-control failure must outrank later terminal cleanup"
        );
        fs::remove_file(path)?;
    }
    fs::remove_file(report.join(terminal_marker))?;

    write_private_new(
        &report.join("exercise.job-control-failed.user-controlled"),
        b"classified\n",
    )?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must reject an unknown job-control filename"
    );
    scratch.cleanup()
}

#[test]
fn package_exercise_phase_diagnostics_are_ordered_fixed_and_payload_free() {
    assert_eq!(
        PACKAGE_EXERCISE_PHASES.map(PackageExercisePhase::marker),
        [
            "exercise.children-validated",
            "exercise.initial-gate-observed",
            "exercise.raw-mode-observed",
            "exercise.post-gate-tui-live",
            "exercise.pre-ready-input-blocked",
            "exercise.tui-startup-sentinel-observed",
            "exercise.initial-input-written",
            "exercise.initial-input-observed",
            "exercise.backend-inference-completed",
            "exercise.tui-response-sentinel-observed",
            "exercise.resize-observed",
            "exercise.suspend-observed",
            "exercise.stopped-state-validated",
            "exercise.suspended-input-blocked",
            "exercise.resume-observed",
            "exercise.resume-gate-observed",
            "exercise.resume-raw-mode-observed",
            "exercise.resume-group-validated",
            "exercise.exit-input-written",
            "exercise.exit-input-observed",
            "exercise.coordinator-exited",
            "exercise.completion-verified",
            "exercise.session-observation-verified",
            "exercise.output-drain-verified",
            "exercise.terminal-restored",
        ]
    );
    assert!(PACKAGE_EXERCISE_PHASES.iter().all(|phase| {
        let marker = phase.marker();
        marker.is_ascii()
            && marker.starts_with("exercise.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
}

#[test]
fn package_recovery_verification_diagnostics_are_ordered_fixed_and_payload_free() {
    assert_eq!(
        PACKAGE_RECOVERY_VERIFICATION_PHASES.map(PackageRecoveryVerificationPhase::marker),
        [
            "recovery.checkpoint-driven",
            "recovery.checkpoint-verified",
            "recovery.observation-only-verified",
            "recovery.request-sent",
            "recovery.owner-write-shutdown",
            "recovery.one-shot-verified",
            "recovery.coordinator-exited",
            "recovery.report-verified",
            "recovery.completion-verified",
            "recovery.tui-group-absent",
            "recovery.app-group-absent",
            "recovery.guardian-group-absent",
            "recovery.reported-groups-absent",
            "recovery.runtime-empty",
        ]
    );
    assert!(PACKAGE_RECOVERY_VERIFICATION_PHASES.iter().all(|phase| {
        let marker = phase.marker();
        marker.is_ascii()
            && marker.starts_with("recovery.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
}

#[test]
fn package_checkpoint_wait_failures_are_closed_fixed_and_payload_free() {
    let markers = [
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
    ]
    .map(package_checkpoint_wait_failure_marker);
    assert_eq!(
        markers,
        [
            "recovery.checkpoint-failed.create",
            "recovery.checkpoint-failed.descriptor",
            "recovery.checkpoint-failed.inherited",
            "recovery.checkpoint-failed.io",
            "recovery.checkpoint-failed.missing-frame",
            "recovery.checkpoint-failed.invalid-frame",
            "recovery.checkpoint-failed.trailing-data",
            "recovery.checkpoint-failed.deadline",
            "recovery.checkpoint-failed.peer-exited",
            "recovery.checkpoint-failed.replay",
            "recovery.checkpoint-failed.too-late",
        ]
    );
    assert!(markers.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("recovery.checkpoint-failed.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
}

#[test]
fn package_reported_group_absence_failures_are_closed_fixed_and_payload_free() {
    assert_eq!(
        [
            PackageReportedGroupAbsenceFailure::Marker,
            PackageReportedGroupAbsenceFailure::Identity,
            PackageReportedGroupAbsenceFailure::Snapshot,
            PackageReportedGroupAbsenceFailure::Residue,
        ]
        .map(PackageReportedGroupAbsenceFailure::marker),
        [
            "recovery.group-absence-failed.marker",
            "recovery.group-absence-failed.identity",
            "recovery.group-absence-failed.snapshot",
            "recovery.group-absence-failed.residue",
        ]
    );
}

#[test]
fn package_official_tui_group_failures_are_closed_fixed_and_payload_free() {
    use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

    let snapshot_errors = [
        PackageProcessSnapshotError::Unstable,
        PackageProcessSnapshotError::Empty,
        PackageProcessSnapshotError::Leader,
        PackageProcessSnapshotError::DuplicateProcess,
        PackageProcessSnapshotError::Identity,
        PackageProcessSnapshotError::LiveState,
        PackageProcessSnapshotError::StoppedState,
        PackageProcessSnapshotError::MissingStoppedMember,
    ];
    let descriptor_errors = [
        ProcessGroupDescriptorScanError::InvalidArgument,
        ProcessGroupDescriptorScanError::ProcessLimit,
        ProcessGroupDescriptorScanError::MemberLimit,
        ProcessGroupDescriptorScanError::DescriptorLimit,
        ProcessGroupDescriptorScanError::ForbiddenIdentityLimit,
        ProcessGroupDescriptorScanError::Deadline,
        ProcessGroupDescriptorScanError::PermissionDenied,
        ProcessGroupDescriptorScanError::ProcessUserMismatch,
        ProcessGroupDescriptorScanError::ProcessChanged,
        ProcessGroupDescriptorScanError::DescriptorChanged,
        ProcessGroupDescriptorScanError::ForbiddenDescriptor,
        ProcessGroupDescriptorScanError::UnsupportedDescriptor,
        ProcessGroupDescriptorScanError::ObservationFailed,
    ];
    let mut markers = vec![
        PackageOfficialTuiGroupFailure::Leader.marker(),
        PackageOfficialTuiGroupFailure::JobIdentity.marker(),
        PackageOfficialTuiGroupFailure::Empty.marker(),
        PackageOfficialTuiGroupFailure::Snapshot.marker(),
        PackageOfficialTuiGroupFailure::NotStablyLiveNoObservation.marker(),
        PackageOfficialTuiGroupFailure::NotStablyLiveMixed.marker(),
    ];
    markers.extend(
        snapshot_errors.map(|error| PackageOfficialTuiGroupFailure::NotStablyLive(error).marker()),
    );
    markers.extend(
        descriptor_errors.map(|error| PackageOfficialTuiGroupFailure::Descriptor(error).marker()),
    );
    assert_eq!(
        markers.as_slice(),
        PACKAGE_OFFICIAL_TUI_GROUP_FAILURE_MARKERS
    );
    assert!(markers.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("exercise.tui-group-validation-failed.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
    let marker_count = markers.len();
    markers.sort_unstable();
    markers.dedup();
    assert_eq!(markers.len(), marker_count);
}

#[test]
fn package_official_tui_descriptor_scan_retries_only_live_target_churn() {
    use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

    let origin = Instant::now();
    let clock = std::cell::Cell::new(origin);
    let deadline = origin + Duration::from_millis(250);
    let mut observations = VecDeque::from([
        Err(ProcessGroupDescriptorScanError::DescriptorChanged),
        Err(ProcessGroupDescriptorScanError::ProcessChanged),
        Ok(7_u8),
    ]);
    let mut observation_calls = 0;
    let mut attempt_deadlines = Vec::new();
    let mut liveness_checks = 0;
    let mut waits = Vec::new();

    let result = retry_package_official_tui_descriptor_scan(
        deadline,
        |attempt_deadline| {
            observation_calls += 1;
            attempt_deadlines.push(attempt_deadline);
            observations
                .pop_front()
                .unwrap_or(Err(ProcessGroupDescriptorScanError::ObservationFailed))
        },
        || {
            liveness_checks += 1;
            Ok(())
        },
        |duration| {
            waits.push(duration);
            clock.set(clock.get() + duration);
        },
        || clock.get(),
    );

    assert_eq!(result, Ok(7));
    assert_eq!(observation_calls, 3);
    assert_eq!(attempt_deadlines, vec![deadline; 3]);
    assert_eq!(liveness_checks, 6);
    assert_eq!(waits, vec![Duration::from_millis(50); 2]);
    assert!(observations.is_empty());
    assert!(clock.get() < deadline);
}

#[test]
fn package_official_tui_descriptor_scan_never_retries_policy_failures() {
    use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

    for error in [
        ProcessGroupDescriptorScanError::UnsupportedDescriptor,
        ProcessGroupDescriptorScanError::ForbiddenDescriptor,
    ] {
        let origin = Instant::now();
        let mut observation_calls = 0;
        let mut liveness_checks = 0;
        let mut waits = 0;
        let result = retry_package_official_tui_descriptor_scan::<(), _, _, _, _>(
            origin + Duration::from_secs(1),
            |_| {
                observation_calls += 1;
                Err(error)
            },
            || {
                liveness_checks += 1;
                Ok(())
            },
            |_| waits += 1,
            || origin,
        );

        assert_eq!(
            result,
            Err(PackageOfficialTuiGroupFailure::Descriptor(error))
        );
        assert_eq!(observation_calls, 1);
        assert_eq!(liveness_checks, 1);
        assert_eq!(waits, 0);
    }
}

#[test]
fn package_official_tui_descriptor_scan_stops_retry_when_job_identity_is_lost() {
    use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

    let origin = Instant::now();
    let mut observation_calls = 0;
    let mut liveness_checks = 0;
    let mut waits = 0;
    let result = retry_package_official_tui_descriptor_scan::<(), _, _, _, _>(
        origin + Duration::from_secs(1),
        |_| {
            observation_calls += 1;
            Err(ProcessGroupDescriptorScanError::DescriptorChanged)
        },
        || {
            liveness_checks += 1;
            if liveness_checks == 1 {
                Ok(())
            } else {
                Err(PackageOfficialTuiGroupFailure::JobIdentity)
            }
        },
        |_| waits += 1,
        || origin,
    );

    assert_eq!(result, Err(PackageOfficialTuiGroupFailure::JobIdentity));
    assert_eq!(observation_calls, 1);
    assert_eq!(liveness_checks, 2);
    assert_eq!(waits, 0);
}

#[test]
fn package_official_tui_descriptor_scan_success_must_finish_before_the_deadline() {
    use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

    let origin = Instant::now();
    let clock = std::cell::Cell::new(origin);
    let deadline = origin + Duration::from_millis(100);
    let mut liveness_checks = 0;
    let result = retry_package_official_tui_descriptor_scan::<u8, _, _, _, _>(
        deadline,
        |_| {
            clock.set(deadline);
            Ok(7)
        },
        || {
            liveness_checks += 1;
            Ok(())
        },
        |_| panic!("a successful scan must not enter the retry wait"),
        || clock.get(),
    );

    assert_eq!(
        result,
        Err(PackageOfficialTuiGroupFailure::Descriptor(
            ProcessGroupDescriptorScanError::Deadline
        ))
    );
    assert_eq!(liveness_checks, 2);
}

#[test]
fn package_official_tui_descriptor_scan_rejects_identity_loss_after_success() {
    let origin = Instant::now();
    let mut observation_calls = 0;
    let mut liveness_checks = 0;
    let result = retry_package_official_tui_descriptor_scan::<u8, _, _, _, _>(
        origin + Duration::from_secs(1),
        |_| {
            observation_calls += 1;
            Ok(7)
        },
        || {
            liveness_checks += 1;
            if liveness_checks == 1 {
                Ok(())
            } else {
                Err(PackageOfficialTuiGroupFailure::JobIdentity)
            }
        },
        |_| panic!("a successful scan must not enter the retry wait"),
        || origin,
    );

    assert_eq!(result, Err(PackageOfficialTuiGroupFailure::JobIdentity));
    assert_eq!(observation_calls, 1);
    assert_eq!(liveness_checks, 2);
}

#[test]
fn package_official_tui_descriptor_scan_closes_persistent_churn_at_one_deadline() {
    use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

    let origin = Instant::now();
    let clock = std::cell::Cell::new(origin);
    let deadline = origin + Duration::from_millis(125);
    let mut observation_calls = 0;
    let mut liveness_checks = 0;
    let mut waits = Vec::new();
    let result = retry_package_official_tui_descriptor_scan::<(), _, _, _, _>(
        deadline,
        |_| {
            observation_calls += 1;
            Err(ProcessGroupDescriptorScanError::DescriptorChanged)
        },
        || {
            liveness_checks += 1;
            Ok(())
        },
        |duration| {
            waits.push(duration);
            clock.set(clock.get() + duration);
        },
        || clock.get(),
    );

    assert_eq!(
        result,
        Err(PackageOfficialTuiGroupFailure::Descriptor(
            ProcessGroupDescriptorScanError::Deadline
        ))
    );
    assert_eq!(observation_calls, 3);
    assert_eq!(liveness_checks, 6);
    assert_eq!(
        waits,
        vec![
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_millis(25),
        ]
    );
    assert_eq!(clock.get(), deadline);
}

#[test]
fn package_live_snapshot_failure_state_preserves_one_reason_and_closes_mixed_sequences() {
    let state = PackageLiveSnapshotFailureState::NoObservation
        .observe(PackageProcessSnapshotError::LiveState)
        .observe(PackageProcessSnapshotError::LiveState);
    assert_eq!(
        state.failure(),
        PackageOfficialTuiGroupFailure::NotStablyLive(PackageProcessSnapshotError::LiveState)
    );
    let mixed = state.observe(PackageProcessSnapshotError::Unstable);
    assert_eq!(
        mixed.failure(),
        PackageOfficialTuiGroupFailure::NotStablyLiveMixed
    );
    assert_eq!(
        PackageLiveSnapshotFailureState::NoObservation.failure(),
        PackageOfficialTuiGroupFailure::NotStablyLiveNoObservation
    );
}

#[test]
fn package_live_group_snapshot_transient_errors_retry_until_two_stable_observations() {
    let tui = PackageChildMarker {
        pid: 101,
        pgid: 101,
    };
    let valid = vec![
        package_process_state_for_test(101, b'S'),
        package_process_state_for_test(102, b'R'),
    ];
    let mut observations = VecDeque::from([
        None,
        Some(valid.clone()),
        None,
        Some(valid.clone()),
        Some(valid),
    ]);
    let origin = Instant::now();
    let clock = std::cell::Cell::new(origin);
    let deadline = origin + Duration::from_millis(250);
    let mut waits = Vec::new();
    let mut observer_calls = 0;

    let result = validate_live_official_tui_group_with_snapshot_observer(
        tui,
        deadline,
        501,
        |_| {
            observer_calls += 1;
            match observations.pop_front() {
                Some(Some(snapshot)) => Ok(snapshot),
                Some(None) => Err("a short-lived package descendant exited".into()),
                None => Err("the package snapshot observer exceeded its test plan".into()),
            }
        },
        |duration| {
            waits.push(duration);
            clock.set(clock.get() + duration);
        },
        || clock.get(),
    );

    assert_eq!(result, Ok(()));
    assert_eq!(observer_calls, 5);
    assert!(observations.is_empty());
    assert_eq!(waits, vec![Duration::from_millis(50); 4]);
    assert!(clock.get() < deadline);
}

#[test]
fn package_live_group_snapshot_errors_close_only_at_the_absolute_deadline() {
    let tui = PackageChildMarker {
        pid: 101,
        pgid: 101,
    };
    let origin = Instant::now();
    let clock = std::cell::Cell::new(origin);
    let deadline = origin + Duration::from_millis(125);
    let mut waits = Vec::new();
    let mut observer_calls = 0;

    let result = validate_live_official_tui_group_with_snapshot_observer(
        tui,
        deadline,
        501,
        |_| {
            observer_calls += 1;
            Err("a short-lived package descendant exited".into())
        },
        |duration| {
            waits.push(duration);
            clock.set(clock.get() + duration);
        },
        || clock.get(),
    );

    assert_eq!(result, Err(PackageOfficialTuiGroupFailure::Snapshot));
    assert_eq!(observer_calls, 3);
    assert_eq!(
        waits,
        vec![
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_millis(25),
        ]
    );
    assert_eq!(clock.get(), deadline);
}

#[test]
fn package_live_group_snapshot_pair_must_complete_before_the_absolute_deadline() {
    let tui = PackageChildMarker {
        pid: 101,
        pgid: 101,
    };
    let valid = vec![
        package_process_state_for_test(101, b'S'),
        package_process_state_for_test(102, b'R'),
    ];
    let mut observations = VecDeque::from([valid.clone(), valid]);
    let origin = Instant::now();
    let clock = std::cell::Cell::new(origin);
    let deadline = origin + Duration::from_millis(100);
    let mut observer_calls = 0;

    let result = validate_live_official_tui_group_with_snapshot_observer(
        tui,
        deadline,
        501,
        |_| {
            observer_calls += 1;
            let snapshot = observations.pop_front().ok_or_else(|| -> Box<dyn Error> {
                "the package snapshot observer exceeded its test plan".into()
            })?;
            if observer_calls == 2 {
                clock.set(deadline);
            }
            Ok(snapshot)
        },
        |duration| clock.set(clock.get() + duration),
        || clock.get(),
    );

    assert_eq!(
        result,
        Err(PackageOfficialTuiGroupFailure::NotStablyLiveNoObservation)
    );
    assert_eq!(observer_calls, 2);
    assert!(observations.is_empty());
    assert_eq!(clock.get(), deadline);
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_official_tui_group_catalog()
-> Result<(), Box<dyn Error>> {
    use std::collections::BTreeSet;

    let catalog: BTreeSet<_> = PACKAGE_OFFICIAL_TUI_GROUP_FAILURE_MARKERS
        .iter()
        .copied()
        .collect();
    assert_eq!(
        catalog.len(),
        PACKAGE_OFFICIAL_TUI_GROUP_FAILURE_MARKERS.len()
    );

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let terminal_marker = PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0];
    write_private_new(&report.join(terminal_marker), b"classified\n")?;
    for marker in PACKAGE_OFFICIAL_TUI_GROUP_FAILURE_MARKERS.iter().copied() {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker),
            "the first exercise failure must outrank a later cleanup failure"
        );
        fs::remove_file(path)?;
    }
    fs::remove_file(report.join(terminal_marker))?;

    let unknown = report.join("exercise.tui-group-validation-failed.user-controlled");
    write_private_new(&unknown, b"classified\n")?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must not return a prefix match or a raw report filename"
    );
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_startup_stage_catalog()
-> Result<(), Box<dyn Error>> {
    use std::collections::BTreeSet;

    let catalog: BTreeSet<_> = PACKAGED_STARTUP_FAILURE_MARKERS.iter().copied().collect();
    assert_eq!(catalog.len(), PACKAGED_STARTUP_FAILURE_MARKERS.len());
    assert!(catalog.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("startup-failure.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    for marker in PACKAGED_STARTUP_FAILURE_MARKERS.iter().copied() {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }

    let unknown = report.join("startup-failure.user-controlled");
    write_private_new(&unknown, b"classified\n")?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must not return a prefix match or a raw report filename"
    );
    scratch.cleanup()
}

#[test]
fn package_group_absence_accepts_explicit_not_started_slots_but_rejects_ambiguity()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let deadline = Instant::now() + IO_TIMEOUT;

    write_private_new(
        &report.join(PACKAGED_TUI_NOT_STARTED_MARKER),
        b"classified\n",
    )?;
    assert_eq!(
        verify_reported_package_child_slot_absent(
            &report,
            "tui.child",
            PACKAGED_TUI_NOT_STARTED_MARKER,
            deadline,
        ),
        Ok(())
    );

    write_private_new(&report.join("tui.child"), b"2147483647 2147483647\n")?;
    assert_eq!(
        verify_reported_package_child_slot_absent(
            &report,
            "tui.child",
            PACKAGED_TUI_NOT_STARTED_MARKER,
            deadline,
        ),
        Err(PackageReportedGroupAbsenceFailure::Marker)
    );
    fs::remove_file(report.join("tui.child"))?;
    fs::remove_file(report.join(PACKAGED_TUI_NOT_STARTED_MARKER))?;

    assert_eq!(
        verify_reported_package_child_slot_absent(
            &report,
            "tui.child",
            PACKAGED_TUI_NOT_STARTED_MARKER,
            deadline,
        ),
        Err(PackageReportedGroupAbsenceFailure::Marker)
    );
    write_private_new(
        &report.join(PACKAGED_TUI_NOT_STARTED_MARKER),
        b"malformed\n",
    )?;
    assert_eq!(
        verify_reported_package_child_slot_absent(
            &report,
            "tui.child",
            PACKAGED_TUI_NOT_STARTED_MARKER,
            deadline,
        ),
        Err(PackageReportedGroupAbsenceFailure::Marker)
    );
    scratch.cleanup()
}

#[test]
fn package_process_group_snapshot_parses_current_platform_output_for_absent_group()
-> Result<(), Box<dyn Error>> {
    assert!(package_process_group_snapshot(i32::MAX)?.is_empty());
    Ok(())
}

#[test]
fn package_phase_markers_are_private_monotonic_and_retention_has_priority()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;

    record_package_exercise_phase(&report, PackageExercisePhase::InitialGateObserved);
    record_package_exercise_phase(&report, PackageExercisePhase::RawModeObserved);
    let raw_marker = report.join(PackageExercisePhase::RawModeObserved.marker());
    assert_eq!(fs::read(&raw_marker)?, b"reached\n");
    let metadata = fs::symlink_metadata(&raw_marker)?;
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(write_private_new(&raw_marker, b"replacement\n").is_err());
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_phase_from_report(&report),
        PackageExercisePhase::RawModeObserved.marker()
    );

    record_package_diagnostic_marker(&report, "guardian-retained");
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_phase_from_report(&report),
        "guardian-retained"
    );
    record_package_recovery_verification_phase(
        &report,
        PackageRecoveryVerificationPhase::RequestSent,
    );
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_phase_from_report(&report),
        PackageRecoveryVerificationPhase::RequestSent.marker()
    );
    record_package_diagnostic_marker(
        &report,
        "guardian-retained.termination-cause.natural-tui-eof",
    );
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        Some("guardian-retained.termination-cause.natural-tui-eof")
    );
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_compatibility_catalog()
-> Result<(), Box<dyn Error>> {
    use std::collections::BTreeSet;

    let catalog: BTreeSet<_> = PACKAGED_COMPATIBILITY_FAILURE_MARKERS
        .iter()
        .copied()
        .collect();
    assert_eq!(catalog.len(), PACKAGED_COMPATIBILITY_FAILURE_MARKERS.len());
    assert!(catalog.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("startup-failure.compatibility.subtype.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    for marker in PACKAGED_COMPATIBILITY_FAILURE_MARKERS.iter().copied() {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }

    let unknown = report.join("startup-failure.compatibility.subtype.user-controlled");
    write_private_new(&unknown, b"classified\n")?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must not return a prefix match or a raw report filename"
    );
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_app_socket_catalog()
-> Result<(), Box<dyn Error>> {
    use std::collections::BTreeSet;

    let catalog: BTreeSet<_> = PACKAGED_APP_SOCKET_FAILURE_MARKERS
        .iter()
        .copied()
        .collect();
    assert_eq!(catalog.len(), PACKAGED_APP_SOCKET_FAILURE_MARKERS.len());
    assert!(catalog.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("startup-failure.app-socket.subtype.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let session_fallback = report.join("startup-failure.session-readiness");
    let retained_fallback = report.join("guardian-recovery.retained");
    write_private_new(&session_fallback, b"classified\n")?;
    write_private_new(&retained_fallback, b"classified\n")?;
    for marker in PACKAGED_APP_SOCKET_FAILURE_MARKERS.iter().copied() {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        Some("startup-failure.session-readiness"),
        "a fixed generic fallback must remain available without a subtype"
    );
    fs::remove_file(session_fallback)?;
    fs::remove_file(retained_fallback)?;

    let unknown = report.join("startup-failure.app-socket.subtype.user-controlled");
    write_private_new(&unknown, b"classified\n")?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must not return a prefix match or a raw report filename"
    );
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_session_startup_catalog()
-> Result<(), Box<dyn Error>> {
    use std::collections::BTreeSet;

    let catalog: BTreeSet<_> = PACKAGED_SESSION_STARTUP_FAILURE_MARKERS
        .iter()
        .copied()
        .collect();
    assert_eq!(
        catalog.len(),
        PACKAGED_SESSION_STARTUP_FAILURE_MARKERS.len()
    );
    assert!(catalog.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("startup-failure.session-readiness.subtype.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    write_private_new(
        &report.join("startup-failure.session-readiness"),
        b"classified\n",
    )?;
    for marker in PACKAGED_SESSION_STARTUP_FAILURE_MARKERS.iter().copied() {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        Some("startup-failure.session-readiness")
    );
    fs::remove_file(report.join("startup-failure.session-readiness"))?;

    write_private_new(
        &report.join("startup-failure.session-readiness.subtype.user-controlled"),
        b"classified\n",
    )?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must not return a prefix match or a raw report filename"
    );
    fs::remove_file(report.join("startup-failure.session-readiness.subtype.user-controlled"))?;
    for unknown in [
        "startup-failure.session-readiness.subtype.readiness-relay",
        "startup-failure.session-readiness.subtype.readiness-relay.timeout.extra",
    ] {
        let path = report.join(unknown);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            None,
            "the scanner must reject prefix-only and extended relay markers"
        );
        fs::remove_file(path)?;
    }
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_session_terminal_catalog()
-> Result<(), Box<dyn Error>> {
    use std::collections::BTreeSet;

    let catalog: BTreeSet<_> = PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS
        .iter()
        .copied()
        .collect();
    assert_eq!(
        catalog.len(),
        PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS.len()
    );
    assert!(catalog.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("session-terminal.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    for marker in PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS.iter().copied() {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }

    write_private_new(
        &report.join("session-terminal.user-controlled"),
        b"classified\n",
    )?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must reject unknown terminal diagnostic filenames"
    );
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_does_not_promote_a_clean_natural_tui_exit()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    for marker in [
        "session-terminal.termination-cause.natural-tui-eof",
        "session-terminal.operation.none",
        "session-terminal.tui.exit-0",
        "session-terminal.worker.joined-clean",
        "session-terminal.cleanup.clean",
        "session-terminal.session.completed",
        "session-terminal.guardian-exit.success",
    ] {
        write_private_new(&report.join(marker), b"classified\n")?;
    }
    record_package_exercise_phase(&report, PackageExercisePhase::BackendInferenceCompleted);

    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None
    );
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_or_phase_from_report(&report),
        "exercise.backend-inference-completed"
    );
    scratch.cleanup()
}

#[test]
fn package_session_observation_validation_has_closed_payload_free_failure_subtypes()
-> Result<(), Box<dyn Error>> {
    let expected_input = [
        PACKAGE_SUPERVISOR_INITIAL_INPUT,
        PACKAGE_SUPERVISOR_EXIT_INPUT,
    ]
    .concat();
    let valid = PackagedSessionObservation {
        initial_size: Some((37, 111)),
        resized_sizes: vec![(41, 123)],
        resumed_sizes: vec![(43, 125)],
        suspend_count: 1,
        input: expected_input.clone(),
        output_sentinel_seen: true,
        shutdown_observed: true,
        termination_cause: Some(PackagedObservedTerminationCause::NaturalTuiEof),
        operation_error: Some(PackagedObservedOperationError::None),
        tui_disposition: Some(PackagedObservedTuiDisposition::ExitZero),
        worker_join: Some(PackagedObservedWorkerJoin::JoinedClean),
        cleanup_clean: Some(true),
        session_status: Some(PackagedObservedSessionStatus::Completed),
        guardian_exit: Some(PackagedObservedGuardianExit::Success),
        integrity_failure: None,
        observation_failed: false,
    };
    assert_eq!(
        validate_package_session_observation(&valid, &expected_input),
        Ok(())
    );

    let mut failures = Vec::new();
    let mut observation = valid.clone();
    observation.observation_failed = true;
    failures.push((
        observation,
        PackageSessionObservationFailure::ObserverUnclassified,
    ));
    for (integrity, expected) in [
        (
            PackagedObservationIntegrityFailure::MarkerWrite,
            PackageSessionObservationFailure::ObserverMarkerWrite,
        ),
        (
            PackagedObservationIntegrityFailure::OutputOrder,
            PackageSessionObservationFailure::ObserverOutputOrder,
        ),
        (
            PackagedObservationIntegrityFailure::InitialSize,
            PackageSessionObservationFailure::ObserverInitialSize,
        ),
        (
            PackagedObservationIntegrityFailure::InputOrder,
            PackageSessionObservationFailure::ObserverInputOrder,
        ),
        (
            PackagedObservationIntegrityFailure::InputLengthOverflow,
            PackageSessionObservationFailure::ObserverInputLengthOverflow,
        ),
        (
            PackagedObservationIntegrityFailure::InputLimit,
            PackageSessionObservationFailure::ObserverInputLimit,
        ),
        (
            PackagedObservationIntegrityFailure::InputPersist,
            PackageSessionObservationFailure::ObserverInputPersist,
        ),
        (
            PackagedObservationIntegrityFailure::DuplicateShutdown,
            PackageSessionObservationFailure::ObserverDuplicateShutdown,
        ),
    ] {
        let mut observation = valid.clone();
        observation.observation_failed = true;
        observation.integrity_failure = Some(integrity);
        failures.push((observation, expected));
    }
    let mut observation = valid.clone();
    observation.output_sentinel_seen = false;
    failures.push((observation, PackageSessionObservationFailure::Output));
    let mut observation = valid.clone();
    observation.initial_size = Some((1, 1));
    failures.push((observation, PackageSessionObservationFailure::InitialSize));
    let mut observation = valid.clone();
    observation.resized_sizes.push((99, 99));
    failures.push((observation, PackageSessionObservationFailure::Resize));
    let mut observation = valid.clone();
    observation.resumed_sizes.clear();
    failures.push((observation, PackageSessionObservationFailure::Resume));
    let mut observation = valid.clone();
    observation.suspend_count = 2;
    failures.push((observation, PackageSessionObservationFailure::Suspend));
    let mut observation = valid.clone();
    observation.input.extend_from_slice(b"private-extra-input");
    failures.push((observation, PackageSessionObservationFailure::Input));
    let mut observation = valid;
    observation.session_status = Some(PackagedObservedSessionStatus::Failed);
    failures.push((observation, PackageSessionObservationFailure::Terminal));

    for (observation, expected) in failures {
        let failure = require_rejected_test_result(
            validate_package_session_observation(&observation, &expected_input),
            "invalid package session observation was accepted",
        )?;
        assert_eq!(failure, expected);
        assert!(PACKAGE_SESSION_OBSERVATION_FAILURE_MARKERS.contains(&failure.marker()));
        let diagnostic = failure.to_string();
        assert_eq!(diagnostic, "package session observation failed");
        assert!(!diagnostic.contains("private-extra-input"));
    }
    Ok(())
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_retained_operation_catalog()
-> Result<(), Box<dyn Error>> {
    use std::collections::BTreeSet;

    let catalog: BTreeSet<_> = PACKAGED_SESSION_RETAINED_OPERATION_MARKERS
        .iter()
        .copied()
        .collect();
    assert_eq!(
        catalog.len(),
        PACKAGED_SESSION_RETAINED_OPERATION_MARKERS.len()
    );
    assert!(catalog.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("guardian-retained.session-operation.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    for marker in PACKAGED_SESSION_RETAINED_OPERATION_MARKERS.iter().copied() {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }

    write_private_new(
        &report.join("guardian-retained.session-operation.user-controlled"),
        b"classified\n",
    )?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must reject an unknown retained-operation filename"
    );
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_recovery_drive_catalog()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;

    for marker in PACKAGE_RECOVERY_DRIVE_FAILURE_MARKERS {
        assert!(marker.is_ascii() && marker.starts_with("recovery.drive-failed."));
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }

    write_private_new(
        &report.join("recovery.drive-failed.user-controlled"),
        b"classified\n",
    )?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must reject an unknown recovery-drive filename"
    );
    scratch.cleanup()
}

#[test]
fn package_recovery_drive_failures_are_closed_fixed_and_payload_free() -> Result<(), Box<dyn Error>>
{
    let variants = [
        PackageRecoveryDriveFailure::InitialGate,
        PackageRecoveryDriveFailure::RawMode,
        PackageRecoveryDriveFailure::StartupSentinel,
        PackageRecoveryDriveFailure::InitialInputWrite,
        PackageRecoveryDriveFailure::InitialInputObservation,
        PackageRecoveryDriveFailure::Inference,
        PackageRecoveryDriveFailure::ResponseSentinel,
        PackageRecoveryDriveFailure::ExitInputWrite,
        PackageRecoveryDriveFailure::ExitInputObservation,
    ];
    assert_eq!(
        variants.map(PackageRecoveryDriveFailure::marker),
        PACKAGE_RECOVERY_DRIVE_FAILURE_MARKERS
    );
    let markers: BTreeSet<_> = variants
        .iter()
        .copied()
        .map(PackageRecoveryDriveFailure::marker)
        .collect();
    assert_eq!(markers.len(), variants.len());
    assert!(markers.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("recovery.drive-failed.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
    assert!(variants.iter().all(|failure| {
        failure.to_string() == "the package retained-recovery drive failed"
            && !format!("{failure:?}").contains("private")
    }));

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    classify_package_recovery_drive_stage(
        &report,
        PackageRecoveryDriveFailure::InitialGate,
        Ok::<_, &str>(()),
    )?;
    assert!(
        !report
            .join(PackageRecoveryDriveFailure::InitialGate.marker())
            .exists()
    );
    let error = require_rejected_test_result(
        classify_package_recovery_drive_stage::<(), _>(
            &report,
            PackageRecoveryDriveFailure::InitialGate,
            Err("private provider payload and path"),
        ),
        "a failed retained-recovery drive stage was accepted",
    )?;
    assert_eq!(
        error.to_string(),
        "the package retained-recovery drive failed"
    );
    assert!(!format!("{error:?}").contains("private provider"));
    assert_eq!(
        read_private_bounded(
            &report.join(PackageRecoveryDriveFailure::InitialGate.marker()),
            64,
        )?,
        b"classified\n"
    );
    scratch.cleanup()
}

#[test]
fn package_recovery_failure_evidence_is_immutable_distinct_and_causally_typed()
-> Result<(), Box<dyn Error>> {
    let drive = PackageRecoveryDriveFailure::InitialGate;
    let later_terminal =
        "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-write";
    let startup = FixedPackageStartupFailure::from_marker(later_terminal)
        .ok_or("the closed startup catalog did not construct fixed evidence")?;

    let mut unselected = PackageRecoveryFailureEvidence::default();
    unselected.snapshot_secondary(Some(later_terminal));
    assert_eq!(
        unselected.secondary_marker(),
        None,
        "a candidate without a selected primary became duplicate secondary evidence"
    );

    let mut drive_evidence = PackageRecoveryFailureEvidence::default();
    drive_evidence.snapshot_error(&drive);
    drive_evidence.snapshot_error(&PackageRecoveryDriveFailure::RawMode);
    drive_evidence.snapshot_secondary(Some(drive.marker()));
    assert_eq!(
        drive_evidence.primary_marker(),
        Some(PackageRecoveryDriveFailure::InitialGate.marker())
    );
    assert_eq!(drive_evidence.secondary_marker(), None);
    drive_evidence.snapshot_secondary(Some(later_terminal));
    drive_evidence.snapshot_secondary(Some(PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[1]));
    assert_eq!(drive_evidence.secondary_marker(), Some(later_terminal));

    let startup_error = PackageRecoveryStartupDriveFailure::new(startup, drive);
    let mut startup_evidence = PackageRecoveryFailureEvidence::default();
    startup_evidence.snapshot_error(&startup_error);
    startup_evidence.snapshot_secondary(Some(startup.marker()));
    startup_evidence.snapshot_secondary(Some(drive.marker()));
    startup_evidence.snapshot_secondary(Some("startup-failure.session-readiness"));
    assert_eq!(startup_evidence.primary_marker(), Some(drive.marker()));
    assert_eq!(startup_evidence.drive_context(), Some(drive));
    assert_eq!(startup_evidence.secondary_marker(), Some(startup.marker()));
    startup_evidence.snapshot_secondary(Some(later_terminal));
    assert_eq!(startup_evidence.secondary_marker(), Some(later_terminal));
    Ok(())
}

#[test]
fn retained_drive_failure_consumes_one_activation_before_returning_the_primary_error()
-> Result<(), Box<dyn Error>> {
    let mut activation_calls = 0_u8;
    let result = activate_selected_recovery_after_drive(
        Err(Box::new(PackageRecoveryDriveFailure::InitialGate)),
        Ok(()),
        None,
        || {
            activation_calls = activation_calls.saturating_add(1);
            Ok(())
        },
    );
    let error = require_rejected_test_result(
        result,
        "a retained drive failure was swallowed after recovery activation",
    )?;

    assert_eq!(activation_calls, 1);
    assert_eq!(
        error.downcast_ref::<PackageRecoveryDriveFailure>(),
        Some(&PackageRecoveryDriveFailure::InitialGate)
    );
    Ok(())
}

#[test]
fn retained_recovery_activation_is_once_only_with_fixed_error_precedence()
-> Result<(), Box<dyn Error>> {
    let mut drive_calls = 0_u8;
    let drive_result = activate_selected_recovery_after_drive(
        Err(Box::new(PackageRecoveryDriveFailure::InitialGate)),
        Ok(()),
        None,
        || {
            drive_calls = drive_calls.saturating_add(1);
            Err(Box::new(PackageRecoveryObservationFailure::CoordinatorWait))
        },
    );
    let drive_error = require_rejected_test_result(
        drive_result,
        "a drive error was replaced by a later activation result",
    )?;
    assert_eq!(drive_calls, 1);
    assert_eq!(
        drive_error.downcast_ref::<PackageRecoveryDriveFailure>(),
        Some(&PackageRecoveryDriveFailure::InitialGate)
    );

    let mut checkpoint_calls = 0_u8;
    let checkpoint_result = activate_selected_recovery_after_drive(
        Ok(()),
        Err(CompletionError::RecoveryDeadline),
        None,
        || {
            checkpoint_calls = checkpoint_calls.saturating_add(1);
            Ok(())
        },
    );
    let checkpoint_error = require_rejected_test_result(
        checkpoint_result,
        "a checkpoint error was swallowed after activation",
    )?;
    assert_eq!(checkpoint_calls, 1);
    assert_eq!(
        checkpoint_error.downcast_ref::<CompletionError>(),
        Some(&CompletionError::RecoveryDeadline)
    );

    let mut observation_calls = 0_u8;
    let observation_result = activate_selected_recovery_after_drive(
        Ok(()),
        Ok(()),
        Some(Err(Box::new(
            PackageRecoveryObservationFailure::CoordinatorExited,
        ))),
        || {
            observation_calls = observation_calls.saturating_add(1);
            Ok(())
        },
    );
    let observation_error = require_rejected_test_result(
        observation_result,
        "an observation error was swallowed after activation",
    )?;
    assert_eq!(observation_calls, 1);
    assert_eq!(
        observation_error.downcast_ref::<PackageRecoveryObservationFailure>(),
        Some(&PackageRecoveryObservationFailure::CoordinatorExited)
    );

    let mut activation_calls = 0_u8;
    let activation_result = activate_selected_recovery_after_drive(Ok(()), Ok(()), None, || {
        activation_calls = activation_calls.saturating_add(1);
        Err(Box::new(PackageRecoveryObservationFailure::CoordinatorWait))
    });
    let activation_error = require_rejected_test_result(
        activation_result,
        "an activation error was swallowed when all earlier stages succeeded",
    )?;
    assert_eq!(activation_calls, 1);
    assert_eq!(
        activation_error.downcast_ref::<PackageRecoveryObservationFailure>(),
        Some(&PackageRecoveryObservationFailure::CoordinatorWait)
    );

    let mut success_calls = 0_u8;
    activate_selected_recovery_after_drive(Ok(()), Ok(()), None, || {
        success_calls = success_calls.saturating_add(1);
        Ok(())
    })?;
    assert_eq!(success_calls, 1);
    Ok(())
}

#[test]
fn retained_initial_gate_wait_observes_only_valid_fixed_startup_failures()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let gate = report.join("initial-gate.live");
    let exact = "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-write";
    let generic = "startup-failure.session-readiness";

    write_private_new(&report.join(exact), b"classified\n")?;
    write_private_new(&report.join(generic), b"classified\n")?;
    let started = Instant::now();
    let observation = wait_for_private_marker_or_fixed_startup_failure(
        &report,
        &gate,
        b"open\n",
        Instant::now() + IO_TIMEOUT,
    )?;
    assert_eq!(
        observation,
        PackageInitialGateObservation::StartupFailure(
            FixedPackageStartupFailure::from_marker(exact)
                .ok_or("the test marker was not in the closed startup catalog")?
        ),
        "the retained startup wait discarded the exact causal marker"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "an allowlisted startup failure did not end the retained startup wait early"
    );
    fs::remove_file(report.join(exact))?;
    fs::remove_file(report.join(generic))?;

    write_private_new(
        &report.join("startup-failure.session-readiness.subtype.user-controlled"),
        b"classified\n",
    )?;
    write_private_new(
        &report.join("startup-failure.session-readiness.subtype.readiness-relay"),
        b"classified\n",
    )?;
    write_private_new(&report.join(exact), b"private payload\n")?;
    let symlink_source = report.join("untrusted-startup-symlink-source");
    write_private_new(&symlink_source, b"classified\n")?;
    std::os::unix::fs::symlink(
        &symlink_source,
        report.join(PACKAGED_SESSION_STARTUP_FAILURE_MARKERS[1]),
    )?;
    let hardlink_source = report.join("untrusted-startup-hardlink-source");
    write_private_new(&hardlink_source, b"classified\n")?;
    fs::hard_link(
        &hardlink_source,
        report.join(PACKAGED_SESSION_STARTUP_FAILURE_MARKERS[2]),
    )?;
    let wrong_mode = report.join(PACKAGED_SESSION_STARTUP_FAILURE_MARKERS[3]);
    write_private_new(&wrong_mode, b"classified\n")?;
    fs::set_permissions(&wrong_mode, fs::Permissions::from_mode(0o640))?;
    write_private_new(
        &report.join(PACKAGED_SESSION_STARTUP_FAILURE_MARKERS[4]),
        b"classified\ntrailing\n",
    )?;
    write_private_new(&gate, b"open\n")?;
    assert_eq!(
        wait_for_private_marker_or_fixed_startup_failure(
            &report,
            &gate,
            b"open\n",
            Instant::now() + IO_TIMEOUT,
        )?,
        PackageInitialGateObservation::Opened
    );
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "unknown, prefix-only, or payload-bearing files became fixed diagnostics"
    );
    scratch.cleanup()
}

#[test]
fn package_recovery_observation_failures_are_closed_fixed_and_scannable()
-> Result<(), Box<dyn Error>> {
    let variants = [
        PackageRecoveryObservationFailure::CoordinatorWait,
        PackageRecoveryObservationFailure::CoordinatorExited,
    ];
    assert_eq!(
        variants.map(PackageRecoveryObservationFailure::marker),
        PACKAGE_RECOVERY_OBSERVATION_FAILURE_MARKERS
    );
    assert!(variants.iter().all(|failure| {
        failure
            .marker()
            .starts_with("recovery.observation-only-failed.")
            && failure.to_string() == "the package observation-only proof failed"
    }));

    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    for marker in PACKAGE_RECOVERY_OBSERVATION_FAILURE_MARKERS {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }
    write_private_new(
        &report.join("recovery.observation-only-failed.user-controlled"),
        b"classified\n",
    )?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None
    );
    scratch.cleanup()
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_backend_catalog()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;

    for &marker in PACKAGE_SESSION_BACKEND_FAILURE_MARKERS {
        assert!(marker.is_ascii() && marker.starts_with("package-backend."));
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker)
        );
        fs::remove_file(path)?;
    }

    write_private_new(
        &report.join("package-backend.response.user-controlled"),
        b"classified\n",
    )?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must reject an unknown backend failure filename"
    );
    scratch.cleanup()
}

#[test]
fn package_final_error_prefers_the_fixed_app_socket_subtype_written_with_its_generic_marker()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    write_packaged_startup_failure_marker(&report, "startup-failure.app-socket");
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_or_phase_from_report(&report),
        "startup-failure.app-socket"
    );

    let subtype = "startup-failure.app-socket.subtype.process.deadline";
    write_packaged_startup_failure_marker(&report, subtype);
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_or_phase_from_report(&report),
        subtype
    );
    let final_error = require_rejected_test_result(
        combine_package_exercise_and_cleanup_at_phase(
            Err("private-provider-detail".into()),
            Ok(()),
            Some(OfficialTuiPackageHarness::latest_fixed_failure_or_phase_from_report(&report)),
        ),
        "a package failure unexpectedly succeeded",
    )?;
    assert_eq!(
        final_error.to_string(),
        format!("package exercise failed at fixed phase {subtype}")
    );
    assert!(!format!("{final_error:?}").contains("private-provider-detail"));
    assert!(final_error.source().is_none());
    scratch.cleanup()
}

/// Runs the checksum-pinned official TUI through the actual production
/// coordinator, guardian driver, provider startup/session owners, PTY pumps,
/// and job-control state machine. The package parent owns the completion pair,
/// passes its transit endpoint across real parent -> coordinator -> guardian
/// exec boundaries, and verifies the exact frame plus EOF itself. The
/// persistent production anchor role and its environment parser do not run.
#[test]
#[ignore = "requires the checksum-pinned official Codex 0.144.4 package"]
fn packaged_codex_official_tui_uses_production_coordinator_guardian_session_pty_and_job_control()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    let executable = package_binary()?;
    let scratch = PackageScratch::create()?;
    let backend = match PackageSessionBackend::spawn() {
        Ok(backend) => backend,
        Err(error) => {
            scratch.cleanup()?;
            return Err(error);
        }
    };
    let mut harness = OfficialTuiPackageHarness::spawn(executable, scratch, backend)?;
    let exercise = harness.exercise();
    let exercise_failure_before_cleanup = exercise
        .as_ref()
        .err()
        .and_then(|_| harness.latest_fixed_failure_detail());
    let exercise_phase_before_cleanup = exercise
        .as_ref()
        .err()
        .map(|_| harness.latest_fixed_phase());
    let cleanup_outcome = harness.cleanup_after_exercise(exercise.is_err());
    let preserved_evidence_root = cleanup_outcome
        .preserved_evidence_root()
        .map(Path::to_path_buf);
    let cleanup = cleanup_outcome.result;
    let cleanup_phase = harness.latest_fixed_cleanup_failure_detail();
    let handoff_probe_phase = harness.latest_handoff_probe_phase();
    let exercise_phase = if exercise.is_err() {
        select_package_failure_phase(
            exercise_failure_before_cleanup,
            exercise_phase_before_cleanup,
            harness.latest_fixed_failure_detail(),
        )
    } else {
        None
    };
    combine_package_exercise_and_cleanup_with_evidence(
        exercise,
        cleanup,
        PackageOperationFailureEvidence::primary(exercise_phase),
        cleanup_phase,
        None,
        handoff_probe_phase,
        preserved_evidence_root,
    )
}

#[test]
#[ignore = "requires the checksum-pinned official Codex 0.144.4 package"]
fn packaged_codex_official_tui_recovers_retained_cleanup_pending_with_four_proofs()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    let executable = package_binary()?;
    let scratch = PackageScratch::create()?;
    let root = scratch.root.clone();
    let backend = match PackageSessionBackend::spawn() {
        Ok(backend) => backend,
        Err(error) => {
            scratch.cleanup()?;
            return Err(error);
        }
    };
    let mut harness = OfficialTuiPackageHarness::spawn_with_recovery_checkpoint(
        executable,
        scratch,
        backend,
        Some(RecoveryCheckpoint::RetainedCleanupPending),
    )?;
    let recovery = harness.request_selected_recovery();
    let recovery_failure_before_cleanup = recovery
        .as_ref()
        .err()
        .and_then(|_| harness.latest_fixed_failure_detail());
    let recovery_phase_before_cleanup = recovery
        .as_ref()
        .err()
        .map(|_| harness.latest_fixed_phase());
    let cleanup_outcome = harness.cleanup_after_exercise(recovery.is_err());
    let preserved_evidence_root = cleanup_outcome
        .preserved_evidence_root()
        .map(Path::to_path_buf);
    let cleanup = cleanup_outcome.result;
    let cleanup_phase = harness.latest_fixed_cleanup_failure_detail();
    let handoff_probe_phase = harness.latest_handoff_probe_phase();
    let recovery_secondary_failure = recovery
        .as_ref()
        .err()
        .and_then(|_| harness.latest_fixed_secondary_failure_detail());
    let recovery_phase = if recovery.is_err() {
        select_package_failure_phase(
            recovery_failure_before_cleanup,
            recovery_phase_before_cleanup,
            harness.latest_fixed_failure_detail(),
        )
    } else {
        None
    };
    let result = combine_package_exercise_and_cleanup_with_evidence(
        recovery,
        cleanup,
        PackageOperationFailureEvidence::new(recovery_phase, recovery_secondary_failure),
        cleanup_phase,
        None,
        handoff_probe_phase,
        preserved_evidence_root,
    );
    if result.is_ok() && root.exists() {
        return Err("four-proof recovery cleanup did not delete package scratch".into());
    }
    result
}

#[test]
fn packaged_codex_deterministic_fixture_recovers_all_seven_production_checkpoints()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    for (checkpoint, _) in PACKAGE_RECOVERY_CHECKPOINT_WIRE_NAMES {
        run_deterministic_recovery_case(checkpoint)?;
    }
    Ok(())
}

#[test]
fn packaged_codex_deterministic_fixture_recovers_all_seven_production_checkpoints_after_owner_eof()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    for (checkpoint, _) in PACKAGE_RECOVERY_CHECKPOINT_WIRE_NAMES {
        run_deterministic_owner_loss_recovery_case(checkpoint)?;
    }
    Ok(())
}

#[test]
fn packaged_deterministic_drive_failure_consumes_recovery_and_cleans() -> Result<(), Box<dyn Error>>
{
    let _process_guard = package_process_test_guard();
    let suite_budget = reserve_package_deterministic_generation()?;
    let scratch = PackageScratch::create()?;
    let root = scratch.root.clone();
    let backend = PackageSessionBackend::spawn_with_disconnected_inference()?;
    let mut harness = OfficialTuiPackageHarness::spawn_deterministic_recovery(
        scratch,
        backend,
        RecoveryCheckpoint::RetainedQuiescing,
        suite_budget,
    )?;
    let exercise = (|| -> Result<(), Box<dyn Error>> {
        if harness.request_selected_recovery().is_ok() {
            return Err("the injected TUI drive failure unexpectedly succeeded".into());
        }
        if harness.recovery_request_state != PackageRecoveryRequestState::Consumed {
            return Err("the failed drive left recovery reusable".into());
        }
        let report = root.join("supervisor-report");
        for marker in [
            "tui-fixture.inference-failed",
            "recovery.checkpoint-verified",
            "recovery.request-sent",
        ] {
            if !report.join(marker).is_file() {
                return Err("the failed drive omitted a fixed recovery marker".into());
            }
        }
        if report
            .join("recovery.checkpoint-failed.invalid-frame")
            .exists()
        {
            return Err("the selected checkpoint entered the completion decoder".into());
        }
        Ok(())
    })();
    let cleanup = harness.cleanup();
    let cleanup_phase = harness.latest_fixed_cleanup_failure_detail();
    combine_package_exercise_and_cleanup_at_phases(exercise, cleanup, None, cleanup_phase)?;
    if root.exists() {
        return Err("failed-drive recovery cleanup retained package scratch".into());
    }
    Ok(())
}

#[test]
fn packaged_deterministic_early_startup_failure_consumes_one_recovery_and_completes_four_proofs()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    let suite_budget = reserve_package_deterministic_generation()?;
    let scratch = PackageScratch::create()?;
    let root = scratch.root.clone();
    let backend = PackageSessionBackend::spawn()?;
    let mut harness = OfficialTuiPackageHarness::spawn_deterministic_startup_failure_recovery(
        scratch,
        backend,
        suite_budget,
    )?;
    let report = root.join("supervisor-report");
    let startup_marker =
        "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-write";

    let started = Instant::now();
    let error = require_rejected_test_result(
        harness.request_selected_recovery(),
        "the injected early startup failure unexpectedly completed the recovery drive",
    )?;
    assert!(
        started.elapsed()
            < PACKAGE_SELECTED_RECOVERY_RECONCILIATION_TIMEOUT + Duration::from_secs(5),
        "the early startup failure slept through the deterministic startup fence"
    );
    let typed = error
        .downcast_ref::<PackageRecoveryStartupDriveFailure>()
        .ok_or("the early startup failure lost its typed causal identity")?;
    assert_eq!(typed.startup.marker(), startup_marker);
    assert_eq!(typed.drive, PackageRecoveryDriveFailure::InitialGate);
    assert_eq!(
        harness.recovery_failure_evidence.primary_marker(),
        Some(PackageRecoveryDriveFailure::InitialGate.marker())
    );
    assert_eq!(
        harness.recovery_failure_evidence.drive_context(),
        Some(PackageRecoveryDriveFailure::InitialGate)
    );
    assert_eq!(
        harness.recovery_request_state,
        PackageRecoveryRequestState::Consumed
    );
    assert!(report.join("recovery.request-sent").is_file());
    let retained_proof_deadline = Instant::now() + IO_TIMEOUT;
    wait_for_private_marker(
        &report.join("guardian-retained.owner.startup-restore"),
        b"classified\n",
        retained_proof_deadline,
    )?;
    wait_for_private_marker(
        &report.join("recovery.guardian-checkpoint.request-verified"),
        b"classified\n",
        retained_proof_deadline,
    )?;
    assert!(
        !report
            .join("recovery.guardian-checkpoint.published")
            .exists()
            && !report.join("recovery.checkpoint-verified").exists(),
        "the startup-owner test hid behind a pre-consumed session checkpoint"
    );
    harness.snapshot_recovery_secondary_failure();
    assert_eq!(
        harness.recovery_failure_evidence.secondary_marker(),
        Some(startup_marker),
        "the generic startup alias masked the exact reproduced secondary evidence"
    );

    let second = PackageGenerationCleanupOperations::request_recovery_once(
        &mut harness,
        Instant::now() + IO_TIMEOUT,
    )?;
    assert_eq!(second, PackageRecoveryRequestObservation::AlreadyConsumed);
    harness.verify_selected_recovery_outcome()?;
    harness.finish_started_generation_cleanup_or_exit();
    let cleanup_evidence = harness
        .generation_cleanup
        .ok_or("the early failure cleanup lost its four-proof evidence")?;
    assert!(cleanup_evidence.exact_coordinator_wait);
    assert!(cleanup_evidence.completion_verified);
    assert!(cleanup_evidence.reported_groups_absent);
    assert!(cleanup_evidence.runtime_empty);
    assert_eq!(
        cleanup_evidence.scratch_decision(),
        PackageScratchCleanupDecision::Delete
    );
    harness.verify_selected_recovery_trigger(PackageRecoveryTrigger::GenerationBoundRequest)?;
    harness.cleanup()?;
    assert!(
        !root.exists(),
        "early startup recovery retained scratch after all four proofs"
    );
    Ok(())
}

#[test]
#[ignore = "focused one-checkpoint diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_startup_queued_only() -> Result<(), Box<dyn Error>>
{
    let _process_guard = package_process_test_guard();
    run_deterministic_recovery_case(RecoveryCheckpoint::StartupQueued)
}

#[test]
#[ignore = "focused one-checkpoint diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_ready_only() -> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    run_deterministic_recovery_case(RecoveryCheckpoint::Ready)
}

#[test]
#[ignore = "focused owner-EOF checkpoint diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_ready_after_owner_eof_only()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    run_deterministic_owner_loss_recovery_case(RecoveryCheckpoint::Ready)
}

#[test]
#[ignore = "focused one-checkpoint diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_active_only() -> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    run_deterministic_recovery_case(RecoveryCheckpoint::Active)
}

#[test]
#[ignore = "focused one-checkpoint diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_suspended_only() -> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    run_deterministic_recovery_case(RecoveryCheckpoint::Suspended)
}

#[test]
#[ignore = "focused cumulative diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_first_three_checkpoints()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    for checkpoint in [
        RecoveryCheckpoint::StartupQueued,
        RecoveryCheckpoint::Ready,
        RecoveryCheckpoint::Active,
    ] {
        run_deterministic_recovery_case(checkpoint)?;
    }
    Ok(())
}

#[test]
#[ignore = "focused one-checkpoint diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_retained_quiescing_only()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    run_deterministic_recovery_case(RecoveryCheckpoint::RetainedQuiescing)
}

#[test]
#[ignore = "focused one-checkpoint diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_retained_restore_pending_only()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    run_deterministic_recovery_case(RecoveryCheckpoint::RetainedRestorePending)
}

#[test]
#[ignore = "focused one-checkpoint diagnostic; exhaustive matrix is nonignored"]
fn packaged_codex_deterministic_fixture_recovers_retained_cleanup_pending_only()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    run_deterministic_recovery_case(RecoveryCheckpoint::RetainedCleanupPending)
}

fn run_deterministic_recovery_case(checkpoint: RecoveryCheckpoint) -> Result<(), Box<dyn Error>> {
    run_deterministic_recovery_case_with_trigger(
        checkpoint,
        PackageRecoveryTrigger::GenerationBoundRequest,
    )
}

fn run_deterministic_owner_loss_recovery_case(
    checkpoint: RecoveryCheckpoint,
) -> Result<(), Box<dyn Error>> {
    run_deterministic_recovery_case_with_trigger(checkpoint, PackageRecoveryTrigger::OwnerEof)
}

fn run_deterministic_recovery_case_with_trigger(
    checkpoint: RecoveryCheckpoint,
    trigger: PackageRecoveryTrigger,
) -> Result<(), Box<dyn Error>> {
    let suite_budget = reserve_package_deterministic_generation()?;
    let scratch = PackageScratch::create()?;
    let root = scratch.root.clone();
    let backend = match PackageSessionBackend::spawn() {
        Ok(backend) => backend,
        Err(error) => {
            scratch.cleanup()?;
            return Err(error);
        }
    };
    let mut harness = OfficialTuiPackageHarness::spawn_deterministic_recovery(
        scratch,
        backend,
        checkpoint,
        suite_budget,
    )?;
    let exercise = (|| -> Result<(), Box<dyn Error>> {
        harness.trigger_selected_recovery(trigger)?;
        let second = PackageGenerationCleanupOperations::request_recovery_once(
            &mut harness,
            Instant::now() + IO_TIMEOUT,
        )?;
        if second != PackageRecoveryRequestObservation::AlreadyConsumed
            || harness.recovery_request_state != PackageRecoveryRequestState::Consumed
        {
            return Err("package recovery request was not one-shot across cleanup".into());
        }
        let report = harness.root()?.join("supervisor-report");
        record_package_recovery_verification_phase(
            &report,
            PackageRecoveryVerificationPhase::OneShotVerified,
        );
        harness.verify_selected_recovery_outcome()?;
        harness.verify_selected_recovery_trigger(trigger)
    })();
    let exercise_failure_before_cleanup = exercise
        .as_ref()
        .err()
        .and_then(|_| harness.latest_fixed_failure_detail());
    let exercise_phase_before_cleanup = exercise
        .as_ref()
        .err()
        .map(|_| harness.latest_fixed_phase());
    let cleanup = harness.cleanup();
    let cleanup_phase = harness.latest_fixed_cleanup_failure_detail();
    let exercise_phase = if exercise.is_err() {
        select_package_failure_phase(
            exercise_failure_before_cleanup,
            exercise_phase_before_cleanup,
            harness.latest_fixed_failure_detail(),
        )
    } else {
        None
    };
    combine_package_exercise_and_cleanup_at_recovery_case(
        exercise,
        cleanup,
        exercise_phase,
        cleanup_phase,
        package_recovery_case_failure_marker(trigger, checkpoint),
    )?;
    if root.exists() {
        return Err(format!(
            "deterministic recovery retained scratch after {}",
            package_recovery_checkpoint_wire_name(checkpoint)
        )
        .into());
    }
    Ok(())
}

/// Closed-over libtest role dispatcher used only by the ignored package E2E.
/// Normal test runs execute this as a no-op; subprocess activation requires a
/// fixed role plus private-root markers prepared by the parent test.
#[test]
fn packaged_codex_official_tui_production_graph_helper() -> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    match std::env::var(PACKAGE_SUPERVISOR_ROLE_ENV).ok().as_deref() {
        None => Ok(()),
        Some(PACKAGE_SUPERVISOR_COORDINATOR_ROLE) => run_package_coordinator_helper(),
        Some(PACKAGE_SUPERVISOR_GUARDIAN_ROLE) => run_package_guardian_helper(),
        Some(_) => Err("package supervisor helper role was invalid".into()),
    }
}

/// Fixed libtest dispatcher reached only through the private generated
/// provider wrapper. A normal test run has no role and remains a no-op.
#[test]
fn packaged_codex_libtest_provider_helper() -> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    let role = match std::env::var(PACKAGE_LIBTEST_PROVIDER_ROLE_ENV) {
        Ok(role) => role,
        Err(std::env::VarError::NotPresent) => return Ok(()),
        Err(_) => return Err("libtest provider role was not UTF-8".into()),
    };
    let activation = parse_package_libtest_provider_activation(
        std::env::var(PACKAGE_LIBTEST_PROVIDER_ROOT_ENV)
            .ok()
            .as_deref(),
        Some(&role),
        std::env::var(PACKAGE_LIBTEST_PROVIDER_APP_SOCKET_ENV)
            .ok()
            .as_deref(),
        std::env::var(PACKAGE_LIBTEST_PROVIDER_REMOTE_ENV)
            .ok()
            .as_deref(),
        std::env::var(PACKAGE_LIBTEST_PROVIDER_THREAD_ENV)
            .ok()
            .as_deref(),
    )?;
    match activation {
        PackageLibtestProviderActivation::AppServer { socket } => {
            run_package_libtest_app_server(&socket)
        }
        PackageLibtestProviderActivation::RemoteTui { remote, thread_id } => {
            run_package_libtest_remote_tui(&remote, &thread_id)
        }
    }
}

/// Closed launcher dispatcher reached only through the private zero-argument
/// wrapper. The production launcher parser remains the sole authority for its
/// fixed contract, target executable, Unix remote, and canonical thread ID.
#[test]
fn packaged_codex_libtest_launcher_helper() -> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    if !super::launcher::internal_launcher_requested() {
        return Ok(());
    }
    match super::launcher::run_exec_launcher() {
        Ok(code) if code == ExitCode::SUCCESS => Ok(()),
        Ok(_) => Err("libtest launcher returned a target failure".into()),
        Err(_) => Err("libtest launcher rejected its production contract".into()),
    }
}

#[test]
fn package_libtest_provider_activation_parser_is_root_bound_and_closed_over_two_exact_roles()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let exercise = (|| -> Result<(), Box<dyn Error>> {
        let runtime = package_libtest_runtime_for_parser_test(&scratch, &Uuid::nil().to_string())?;
        let root = scratch.root.to_str().ok_or("test root was not UTF-8")?;
        let app = format!("unix://{}", runtime.join("app.sock").display());
        let tui = format!("unix://{}", runtime.join("tui.sock").display());
        if !matches!(
            parse_package_libtest_provider_activation(
                Some(root),
                Some("app-server-v1"),
                Some(&app),
                None,
                None,
            ),
            Ok(PackageLibtestProviderActivation::AppServer { .. })
        ) {
            return Err("exact App Server activation was rejected".into());
        }
        if !matches!(
            parse_package_libtest_provider_activation(
                Some(root),
                Some("remote-tui-v1"),
                None,
                Some(&tui),
                Some(PACKAGE_SUPERVISOR_THREAD_ID),
            ),
            Ok(PackageLibtestProviderActivation::RemoteTui { .. })
        ) {
            return Err("exact remote TUI activation was rejected".into());
        }

        let outside = PackageScratch::create()?;
        let outside_exercise = (|| -> Result<(), Box<dyn Error>> {
            let outside_runtime =
                package_libtest_runtime_for_parser_test(&outside, &Uuid::new_v4().to_string())?;
            let outside_app = format!("unix://{}", outside_runtime.join("app.sock").display());
            let wrong_filename = format!("unix://{}", runtime.join("provider.sock").display());
            let wrong_runtime_root = scratch.root.join("not-runtime");
            private_directory(&wrong_runtime_root)?;
            let wrong_runtime =
                wrong_runtime_root.join(format!(".calcifer-supervisor-{}", Uuid::new_v4()));
            private_directory(&wrong_runtime)?;
            let wrong_runtime_app = format!("unix://{}", wrong_runtime.join("app.sock").display());
            for invalid in [
                parse_package_libtest_provider_activation(None, None, None, None, None),
                parse_package_libtest_provider_activation(
                    Some(root),
                    Some("app-server-v1"),
                    Some("tcp://127.0.0.1:9"),
                    None,
                    None,
                ),
                parse_package_libtest_provider_activation(
                    Some(root),
                    Some("app-server-v1"),
                    Some(&app),
                    Some(&tui),
                    None,
                ),
                parse_package_libtest_provider_activation(
                    Some(root),
                    Some("remote-tui-v1"),
                    None,
                    Some(&tui),
                    Some(&Uuid::nil().to_string()),
                ),
                parse_package_libtest_provider_activation(
                    Some(root),
                    Some("arbitrary"),
                    Some(&app),
                    None,
                    None,
                ),
                parse_package_libtest_provider_activation(
                    Some(root),
                    Some("app-server-v1"),
                    Some(&outside_app),
                    None,
                    None,
                ),
                parse_package_libtest_provider_activation(
                    Some(root),
                    Some("app-server-v1"),
                    Some(&wrong_filename),
                    None,
                    None,
                ),
                parse_package_libtest_provider_activation(
                    Some(root),
                    Some("app-server-v1"),
                    Some(&wrong_runtime_app),
                    None,
                    None,
                ),
            ] {
                if invalid.is_ok() {
                    return Err("invalid libtest provider activation was accepted".into());
                }
            }
            Ok(())
        })();
        let outside_cleanup = outside.cleanup();
        combine_package_exercise_and_cleanup(outside_exercise, outside_cleanup)
    })();
    let cleanup = scratch.cleanup();
    combine_package_exercise_and_cleanup(exercise, cleanup)
}

fn package_libtest_runtime_for_parser_test(
    scratch: &PackageScratch,
    runtime_id: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let runtime_root = scratch.root.join("r");
    if !runtime_root.exists() {
        private_directory(&runtime_root)?;
    }
    let runtime = runtime_root.join(format!(".calcifer-supervisor-{runtime_id}"));
    private_directory(&runtime)?;
    Ok(runtime)
}

#[test]
fn package_libtest_server_caps_websocket_messages_and_frames() {
    let config = package_libtest_websocket_config();
    assert_eq!(config.max_message_size, Some(MAX_WEBSOCKET_MESSAGE_BYTES));
    assert_eq!(config.max_frame_size, Some(MAX_WEBSOCKET_MESSAGE_BYTES));
    assert!(!config.accept_unmasked_frames);
}

#[test]
fn package_libtest_provider_wrapper_binds_exact_root_thread_and_socket_shape_without_exec()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let exercise = (|| -> Result<(), Box<dyn Error>> {
        let wrapper = install_packaged_codex_provider_fixture(&scratch)?;
        let script_bytes = fs::read(&wrapper)?;
        if script_bytes.len() > 128 * 1024 {
            return Err("libtest provider wrapper exceeded its test bound".into());
        }
        let script = String::from_utf8(script_bytes)?;
        for required in [
            format!("root='{}'", scratch.root.display()),
            PACKAGE_LIBTEST_PROVIDER_ROOT_ENV.to_owned(),
            format!("[ \"$9\" = '{PACKAGE_SUPERVISOR_THREAD_ID}' ]"),
            "/r/.calcifer-supervisor-".to_owned(),
            "/app.sock)".to_owned(),
            "/tui.sock)".to_owned(),
        ] {
            if !script.contains(&required) {
                return Err("libtest provider wrapper omitted a closed contract field".into());
            }
        }
        if script.contains("unix:///*)") {
            return Err("libtest provider wrapper accepted an unbound Unix socket".into());
        }
        Ok(())
    })();
    let cleanup = scratch.cleanup();
    combine_package_exercise_and_cleanup(exercise, cleanup)
}

#[test]
fn package_libtest_provider_wrapper_is_private_and_rejects_noncanonical_argv()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    let scratch = PackageScratch::create()?;
    private_directory(&scratch.root.join("supervisor-report"))?;
    let wrapper = install_packaged_codex_provider_fixture(&scratch)?;
    let metadata = fs::symlink_metadata(&wrapper)?;
    assert_eq!(fs::canonicalize(&wrapper)?, wrapper);
    assert!(wrapper.starts_with(&scratch.root));
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    assert_eq!(metadata.nlink(), 1);

    let invalid_commands = [
        vec![
            "-c",
            "cli_auth_credentials_store=\"keyring\"",
            "-c",
            "mcp_oauth_credentials_store=\"file\"",
            "app-server",
            "--listen",
            "unix:///tmp/calcifer-app.sock",
        ],
        vec![
            "-c",
            "cli_auth_credentials_store=\"file\"",
            "-c",
            "mcp_oauth_credentials_store=\"file\"",
            "app-server",
            "--listen",
            "tcp://127.0.0.1:9",
        ],
        vec![
            "-c",
            "cli_auth_credentials_store=\"file\"",
            "-c",
            "mcp_oauth_credentials_store=\"file\"",
            "resume",
            "--no-alt-screen",
            "--remote",
            "unix:///tmp/calcifer-relay.sock",
            PACKAGE_SUPERVISOR_THREAD_ID,
            "unexpected",
        ],
        vec![
            "-c",
            "cli_auth_credentials_store=\"file\"",
            "-c",
            "mcp_oauth_credentials_store=\"file\"",
            "resume",
            "--no-alt-screen",
            "--remote",
            "unix:///tmp/calcifer-relay.sock",
            "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
        ],
    ];
    for arguments in invalid_commands {
        let status = Command::new(&wrapper)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert_eq!(status.code(), Some(64));
    }

    scratch.cleanup()
}

#[test]
fn package_libtest_launcher_wrapper_is_private_and_rejects_any_argument()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    let scratch = PackageScratch::create()?;
    let wrapper = install_packaged_tui_launcher_fixture(&scratch)?;
    let metadata = fs::symlink_metadata(&wrapper)?;
    assert_eq!(fs::canonicalize(&wrapper)?, wrapper);
    assert!(wrapper.starts_with(&scratch.root));
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        validate_package_launcher_for_target(
            PackageProviderTarget::DeterministicFixture,
            &scratch.root,
            &wrapper,
        )?,
        wrapper
    );

    let substitute = scratch.root.join("substituted-launcher");
    write_private_executable_new(&substitute, b"#!/bin/sh\nexit 64\n")?;
    assert!(
        validate_package_launcher_for_target(
            PackageProviderTarget::DeterministicFixture,
            &scratch.root,
            &substitute,
        )
        .is_err()
    );
    fs::remove_file(substitute)?;

    for argument in ["arbitrary", "--exact", PACKAGE_SUPERVISOR_THREAD_ID] {
        let status = Command::new(&wrapper)
            .arg(argument)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert_eq!(status.code(), Some(64));
    }
    scratch.cleanup()
}

#[test]
fn package_libtest_provider_app_server_accepts_monitor_and_tui_websockets()
-> Result<(), Box<dyn Error>> {
    let _process_guard = package_process_test_guard();
    let scratch = PackageScratch::create()?;
    private_directory(&scratch.root.join("supervisor-report"))?;
    let wrapper = install_packaged_codex_provider_fixture(&scratch)?;
    let runtime = package_libtest_runtime_for_parser_test(&scratch, &Uuid::new_v4().to_string())?;
    let socket = runtime.join("app.sock");
    let mut command = managed_command(&wrapper, &scratch.codex_home);
    command
        .args(["app-server", "--listen"])
        .arg(format!("unix://{}", socket.display()))
        .current_dir(&scratch.workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;

    let exercise = (|| -> Result<(), Box<dyn Error>> {
        let mut monitor = connect_app_server(&socket, Instant::now() + IO_TIMEOUT)?;
        send_request(
            &mut monitor,
            0,
            "initialize",
            json!({
                "clientInfo": {
                    "name": "calcifer",
                    "title": "Calcifer",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": { "experimentalApi": false }
            }),
        )?;
        let initialized = receive_result(&mut monitor, 0, Instant::now() + IO_TIMEOUT)?;
        require_pinned_initialize(&initialized, &scratch.codex_home)?;
        monitor.send(Message::text(r#"{"method":"initialized"}"#))?;
        monitor.send(Message::text(
            r#"{"id":1,"method":"account/rateLimits/read"}"#,
        ))?;
        let usage = receive_result(&mut monitor, 1, Instant::now() + IO_TIMEOUT)?;
        assert_eq!(
            usage.pointer("/rateLimits/primary/usedPercent"),
            Some(&json!(42))
        );
        monitor.send(Message::text(
            r#"{"id":2,"method":"account/rateLimits/read"}"#,
        ))?;
        let refreshed = receive_result(&mut monitor, 2, Instant::now() + IO_TIMEOUT)?;
        assert_eq!(
            refreshed.pointer("/rateLimits/primary/usedPercent"),
            Some(&json!(42))
        );

        let mut tui = connect_app_server(&socket, Instant::now() + IO_TIMEOUT)?;
        send_request(
            &mut tui,
            11,
            "thread/read",
            json!({ "threadId": PACKAGE_SUPERVISOR_THREAD_ID }),
        )?;
        let read = receive_result(&mut tui, 11, Instant::now() + IO_TIMEOUT)?;
        assert_eq!(
            read.pointer("/thread/id").and_then(Value::as_str),
            Some(PACKAGE_SUPERVISOR_THREAD_ID)
        );
        send_request(
            &mut tui,
            12,
            "thread/resume",
            json!({ "threadId": PACKAGE_SUPERVISOR_THREAD_ID }),
        )?;
        let resumed = receive_result(&mut tui, 12, Instant::now() + IO_TIMEOUT)?;
        assert_eq!(
            resumed.pointer("/thread/id").and_then(Value::as_str),
            Some(PACKAGE_SUPERVISOR_THREAD_ID)
        );
        assert_eq!(
            resumed.get("cwd").and_then(Value::as_str),
            scratch.workspace.to_str()
        );
        drop((monitor, tui));
        Ok(())
    })();

    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id())?)
        .ok_or("libtest App Server child PID was invalid")?;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
    let status = child.wait()?;
    let last_phase = latest_package_libtest_app_phase(&scratch.root.join("supervisor-report"));
    let cleanup = scratch.cleanup();
    if exercise.is_err() {
        return Err(format!(
            "libtest App Server exercise failed after fixed phase {}",
            last_phase.unwrap_or("app-fixture.not-started")
        )
        .into());
    }
    if !status.success() {
        return Err("libtest App Server did not exit cleanly on SIGTERM".into());
    }
    cleanup
}

#[test]
fn package_libtest_provider_inference_uses_only_the_fixed_loopback_config()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let backend = PackageSessionBackend::spawn()?;
    write_private_new(
        &scratch.codex_home.join("config.toml"),
        package_usage_config(backend.address()).as_bytes(),
    )?;
    run_package_libtest_provider_inference(&scratch.codex_home)?;
    backend.wait_for_inference_completion(Instant::now() + IO_TIMEOUT)?;
    backend.cancel_join_and_require_inference_evidence()?;

    fs::remove_file(scratch.codex_home.join("config.toml"))?;
    write_private_new(
        &scratch.codex_home.join("config.toml"),
        br#"base_url = "https://example.com/v1"\n"#,
    )?;
    assert!(package_libtest_provider_backend(&scratch.codex_home).is_err());
    scratch.cleanup()
}

#[test]
fn package_process_snapshot_parser_uses_kernel_job_identity_and_requires_four_ps_fields()
-> Result<(), Box<dyn Error>> {
    let parsed = parse_package_process_group_snapshot_with_job_identity(
        b"101 101 501 T\n102 101 501 S+\n201 201 501 R\n",
        101,
        |pid, process_group| {
            if process_group != 101 || pid == 201 {
                return Err("the parser resolved a non-member job identity".into());
            }
            Ok(101)
        },
    )?;
    assert_eq!(
        parsed,
        vec![
            PackageProcessState {
                pid: 101,
                process_group: 101,
                session: 101,
                user: 501,
                state: b'T',
            },
            PackageProcessState {
                pid: 102,
                process_group: 101,
                session: 101,
                user: 501,
                state: b'S',
            },
        ]
    );
    assert!(
        parse_package_process_group_snapshot_with_job_identity(
            b"101 101 T\n",
            101,
            |_, _| Ok(101),
        )
        .is_err()
    );
    assert!(
        parse_package_process_group_snapshot_with_job_identity(
            b"101 101 501 T extra\n",
            101,
            |_, _| Ok(101),
        )
        .is_err()
    );
    assert!(
        parse_package_process_group_snapshot_with_job_identity(
            b"101 101 501 S\n",
            101,
            |_, _| Err("kernel job identity changed".into()),
        )
        .is_err()
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        parse_package_process_group_snapshot_with_job_identity(b"101 101 -2 S\n", 101, |_, _| Ok(
            101
        ),)?,
        vec![PackageProcessState {
            pid: 101,
            process_group: 101,
            session: 101,
            user: u32::MAX - 1,
            state: b'S',
        }]
    );
    Ok(())
}

fn package_process_state_for_test(pid: i32, state: u8) -> PackageProcessState {
    PackageProcessState {
        pid,
        process_group: 101,
        session: 101,
        user: 501,
        state,
    }
}

#[test]
fn package_live_snapshot_requires_one_unique_leader_exact_domain_and_known_live_states() {
    let tui = PackageChildMarker {
        pid: 101,
        pgid: 101,
    };
    let valid = vec![
        package_process_state_for_test(101, b'S'),
        package_process_state_for_test(102, b'R'),
    ];
    assert_eq!(
        validate_live_official_tui_snapshot(tui, &valid, 501),
        Ok(())
    );
    assert_eq!(
        validate_stable_live_official_tui_snapshots(tui, &valid, &valid, 501),
        Ok(())
    );
    let mut unstable = valid.clone();
    unstable[1].state = b'S';
    assert_eq!(
        validate_stable_live_official_tui_snapshots(tui, &valid, &unstable, 501),
        Err(PackageProcessSnapshotError::Unstable)
    );

    assert!(validate_live_official_tui_snapshot(tui, &valid[1..], 501).is_err());
    assert!(
        validate_live_official_tui_snapshot(
            tui,
            &[
                package_process_state_for_test(101, b'S'),
                package_process_state_for_test(101, b'R'),
            ],
            501,
        )
        .is_err()
    );

    for state in [b'T', b't', b'Z', b'X', b'x', b'E', b'?'] {
        let mut invalid = valid.clone();
        invalid[1].state = state;
        assert!(
            validate_live_official_tui_snapshot(tui, &invalid, 501).is_err(),
            "state {state}"
        );
    }

    for mutate in [
        |member: &mut PackageProcessState| member.user = 502,
        |member: &mut PackageProcessState| member.process_group = 202,
        |member: &mut PackageProcessState| member.session = 202,
    ] {
        let mut invalid = valid.clone();
        mutate(&mut invalid[1]);
        assert!(validate_live_official_tui_snapshot(tui, &invalid, 501).is_err());
    }
}

#[test]
fn package_resume_snapshot_binds_every_stopped_identity_and_constrains_extras() {
    let tui = PackageChildMarker {
        pid: 101,
        pgid: 101,
    };
    let stopped = vec![
        package_process_state_for_test(101, b'T'),
        package_process_state_for_test(102, b'T'),
    ];
    let resumed = vec![
        package_process_state_for_test(101, b'S'),
        package_process_state_for_test(102, b'R'),
    ];
    assert_eq!(
        validate_stopped_official_tui_snapshot(tui, &stopped, 501),
        Ok(())
    );
    assert_eq!(
        validate_resumed_official_tui_snapshot(tui, &stopped, &resumed, 501),
        Ok(())
    );

    let mut partial = resumed.clone();
    partial[1].state = b'T';
    assert!(validate_resumed_official_tui_snapshot(tui, &stopped, &partial, 501).is_err());
    for state in [b'Z', b'X'] {
        let mut terminal = resumed.clone();
        terminal[1].state = state;
        assert!(validate_resumed_official_tui_snapshot(tui, &stopped, &terminal, 501).is_err());
    }
    assert!(validate_resumed_official_tui_snapshot(tui, &stopped, &resumed[..1], 501).is_err());

    for mutate in [
        |member: &mut PackageProcessState| member.user = 502,
        |member: &mut PackageProcessState| member.process_group = 202,
        |member: &mut PackageProcessState| member.session = 202,
    ] {
        let mut changed = resumed.clone();
        mutate(&mut changed[1]);
        assert!(validate_resumed_official_tui_snapshot(tui, &stopped, &changed, 501).is_err());
    }

    let mut valid_extra = resumed.clone();
    valid_extra.push(package_process_state_for_test(103, b'I'));
    assert_eq!(
        validate_resumed_official_tui_snapshot(tui, &stopped, &valid_extra, 501),
        Ok(())
    );
    let mut invalid_extra = valid_extra.clone();
    invalid_extra[2].session = 202;
    assert!(validate_resumed_official_tui_snapshot(tui, &stopped, &invalid_extra, 501).is_err());
    invalid_extra[2] = package_process_state_for_test(103, b'Z');
    assert!(validate_resumed_official_tui_snapshot(tui, &stopped, &invalid_extra, 501).is_err());

    assert!(validate_stopped_official_tui_snapshot(tui, &stopped[1..], 501).is_err());
    let mut invalid_stopped = stopped.clone();
    invalid_stopped[1].state = b'S';
    assert!(validate_stopped_official_tui_snapshot(tui, &invalid_stopped, 501).is_err());
}

#[test]
fn package_resume_snapshot_requires_two_identical_stable_observations() {
    let tui = PackageChildMarker {
        pid: 101,
        pgid: 101,
    };
    let stopped = vec![
        package_process_state_for_test(101, b'T'),
        package_process_state_for_test(102, b'T'),
    ];
    let first = vec![
        package_process_state_for_test(101, b'S'),
        package_process_state_for_test(102, b'R'),
    ];
    assert_eq!(
        validate_stable_resumed_official_tui_snapshots(tui, &stopped, &first, &first, 501,),
        Ok(())
    );

    let mut state_changed = first.clone();
    state_changed[1].state = b'S';
    assert_eq!(
        validate_stable_resumed_official_tui_snapshots(tui, &stopped, &first, &state_changed, 501,),
        Err(PackageProcessSnapshotError::Unstable)
    );
    let mut membership_changed = first.clone();
    membership_changed.push(package_process_state_for_test(103, b'I'));
    assert_eq!(
        validate_stable_resumed_official_tui_snapshots(
            tui,
            &stopped,
            &first,
            &membership_changed,
            501,
        ),
        Err(PackageProcessSnapshotError::Unstable)
    );
}

#[test]
fn package_scratch_runtime_parent_satisfies_the_production_socket_path_bound()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let exercise = (|| -> Result<(), Box<dyn Error>> {
        let runtime_parent = scratch.root.join("r");
        private_directory(&runtime_parent)?;
        validate_packaged_runtime_parent(&runtime_parent)?;
        Ok(())
    })();
    let cleanup = scratch.cleanup();
    combine_package_exercise_and_cleanup(exercise, cleanup)
}

#[test]
fn package_scratch_cleanup_requires_every_started_generation_proof() {
    for mask in 0_u8..16 {
        let evidence = PackageGenerationCleanupEvidence {
            exact_coordinator_wait: mask & 0b0001 != 0,
            completion_verified: mask & 0b0010 != 0,
            reported_groups_absent: mask & 0b0100 != 0,
            runtime_empty: mask & 0b1000 != 0,
        };
        let expected = if mask == 0b1111 {
            PackageScratchCleanupDecision::Delete
        } else {
            PackageScratchCleanupDecision::Retain
        };
        assert_eq!(evidence.scratch_decision(), expected, "mask {mask:04b}");
    }
}

#[test]
fn package_stage_residue_keeps_the_fourth_deletion_proof_unset() -> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let runtime_parent = scratch.root.join("r");
    private_directory(&runtime_parent)?;
    let residue = scratch.compatibility_stage_parent.join("unexpected-stage");
    private_directory(&residue)?;
    let mut evidence = PackageGenerationCleanupEvidence {
        exact_coordinator_wait: true,
        completion_verified: true,
        reported_groups_absent: true,
        runtime_empty: false,
    };

    assert!(verify_package_build_namespaces_empty(&scratch.root).is_err());
    assert_eq!(
        evidence.scratch_decision(),
        PackageScratchCleanupDecision::Retain
    );

    fs::remove_dir(residue)?;
    verify_package_build_namespaces_empty(&scratch.root)?;
    evidence.runtime_empty = true;
    assert_eq!(
        evidence.scratch_decision(),
        PackageScratchCleanupDecision::Delete
    );
    scratch.cleanup()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageCleanupTestEvent {
    NormalCompletionPoll,
    RecoveryRequest,
    ObserveExactCoordinatorState,
    WakeExactCoordinator,
    HealthyLifecycleGrace {
        completion_ready: bool,
        coordinator_reaped: bool,
    },
    ExactCoordinatorFallback,
    CompletionProof,
    ReportedGroupsProof,
    RuntimeProof,
}

struct PackageCleanupTestOperations {
    normal_completion: PackageCompletionObservation,
    recovery_request: PackageRecoveryRequestObservation,
    recovery_request_state: PackageRecoveryRequestState,
    underlying_recovery_requests: usize,
    coordinator_state: PackageExactCoordinatorStateObservation,
    healthy_lifecycle: PackageHealthyLifecycleObservation,
    healthy_lifecycle_failure: Option<PackageCleanupFailure>,
    events: Vec<PackageCleanupTestEvent>,
}

impl PackageGenerationCleanupOperations for PackageCleanupTestOperations {
    fn poll_normal_completion(
        &mut self,
        _deadline: Instant,
    ) -> Result<PackageCompletionObservation, PackageCleanupFailure> {
        self.events
            .push(PackageCleanupTestEvent::NormalCompletionPoll);
        Ok(self.normal_completion)
    }

    fn request_recovery_once(
        &mut self,
        _deadline: Instant,
    ) -> Result<PackageRecoveryRequestObservation, PackageCleanupFailure> {
        self.events.push(PackageCleanupTestEvent::RecoveryRequest);
        if !self.recovery_request_state.begin_attempt() {
            return Ok(PackageRecoveryRequestObservation::AlreadyConsumed);
        }
        self.underlying_recovery_requests += 1;
        Ok(self.recovery_request)
    }

    fn observe_exact_coordinator_state(
        &mut self,
    ) -> Result<PackageExactCoordinatorStateObservation, PackageCleanupFailure> {
        self.events
            .push(PackageCleanupTestEvent::ObserveExactCoordinatorState);
        Ok(self.coordinator_state)
    }

    fn wake_exact_coordinator(&mut self) -> Result<(), PackageCleanupFailure> {
        self.events
            .push(PackageCleanupTestEvent::WakeExactCoordinator);
        Ok(())
    }

    fn observe_healthy_lifecycle(
        &mut self,
        completion_ready: bool,
        coordinator_reaped: bool,
        _deadline: Instant,
    ) -> Result<PackageHealthyLifecycleObservation, PackageCleanupFailure> {
        self.events
            .push(PackageCleanupTestEvent::HealthyLifecycleGrace {
                completion_ready,
                coordinator_reaped,
            });
        if let Some(failure) = self.healthy_lifecycle_failure {
            return Err(failure);
        }
        Ok(self.healthy_lifecycle)
    }

    fn force_reap_exact_coordinator(
        &mut self,
        _term_deadline: Instant,
        _kill_deadline: Instant,
    ) -> Result<(), PackageCleanupFailure> {
        self.events
            .push(PackageCleanupTestEvent::ExactCoordinatorFallback);
        Ok(())
    }

    fn prove_completion(&mut self, _deadline: Instant) -> Result<(), PackageCleanupFailure> {
        self.events.push(PackageCleanupTestEvent::CompletionProof);
        Ok(())
    }

    fn prove_reported_groups_absent(
        &mut self,
        _deadline: Instant,
    ) -> Result<(), PackageCleanupFailure> {
        self.events
            .push(PackageCleanupTestEvent::ReportedGroupsProof);
        Ok(())
    }

    fn prove_runtime_empty(&mut self) -> Result<(), PackageCleanupFailure> {
        self.events.push(PackageCleanupTestEvent::RuntimeProof);
        Ok(())
    }
}

#[test]
fn package_cleanup_request_error_waits_healthy_grace_before_exact_child_fallback()
-> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fence = PackageGenerationDeadlineFence::starting_at(start)?;
    let deadlines = PackageCleanupDeadlines::within_generation(fence, start)?;
    let mut operations = PackageCleanupTestOperations {
        normal_completion: PackageCompletionObservation::Pending,
        recovery_request: PackageRecoveryRequestObservation::AttemptConsumedBoundaryUnknown,
        recovery_request_state: PackageRecoveryRequestState::Available,
        underlying_recovery_requests: 0,
        coordinator_state: PackageExactCoordinatorStateObservation::Stopped,
        healthy_lifecycle: PackageHealthyLifecycleObservation {
            completion_ready: false,
            coordinator_reaped: false,
        },
        healthy_lifecycle_failure: None,
        events: Vec::new(),
    };

    let evidence = drive_package_generation_cleanup(
        &mut operations,
        PackageGenerationCleanupEvidence::default(),
        deadlines,
    )?;

    assert_eq!(
        operations.events,
        vec![
            PackageCleanupTestEvent::NormalCompletionPoll,
            PackageCleanupTestEvent::RecoveryRequest,
            PackageCleanupTestEvent::ObserveExactCoordinatorState,
            PackageCleanupTestEvent::WakeExactCoordinator,
            PackageCleanupTestEvent::HealthyLifecycleGrace {
                completion_ready: false,
                coordinator_reaped: false,
            },
            PackageCleanupTestEvent::ExactCoordinatorFallback,
            PackageCleanupTestEvent::CompletionProof,
            PackageCleanupTestEvent::ReportedGroupsProof,
            PackageCleanupTestEvent::RuntimeProof,
        ]
    );
    assert_eq!(
        operations
            .events
            .iter()
            .filter(|event| **event == PackageCleanupTestEvent::RecoveryRequest)
            .count(),
        1
    );
    assert_eq!(
        evidence.scratch_decision(),
        PackageScratchCleanupDecision::Delete
    );
    Ok(())
}

#[test]
fn package_cleanup_does_not_repeat_an_already_consumed_recovery_request()
-> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fence = PackageGenerationDeadlineFence::starting_at(start)?;
    let deadlines = PackageCleanupDeadlines::within_generation(fence, start)?;
    let mut operations = PackageCleanupTestOperations {
        normal_completion: PackageCompletionObservation::Pending,
        recovery_request: PackageRecoveryRequestObservation::Sent,
        recovery_request_state: PackageRecoveryRequestState::Consumed,
        underlying_recovery_requests: 0,
        coordinator_state: PackageExactCoordinatorStateObservation::Reaped,
        healthy_lifecycle: PackageHealthyLifecycleObservation {
            completion_ready: false,
            coordinator_reaped: true,
        },
        healthy_lifecycle_failure: None,
        events: Vec::new(),
    };

    let evidence = drive_package_generation_cleanup(
        &mut operations,
        PackageGenerationCleanupEvidence::default(),
        deadlines,
    )?;

    assert_eq!(operations.underlying_recovery_requests, 0);
    assert_eq!(
        operations
            .events
            .iter()
            .filter(|event| **event == PackageCleanupTestEvent::RecoveryRequest)
            .count(),
        1
    );
    assert_eq!(
        evidence.scratch_decision(),
        PackageScratchCleanupDecision::Delete
    );
    Ok(())
}

#[test]
fn package_retained_outcome_stops_before_recovery_fallback_or_delete_proofs()
-> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fence = PackageGenerationDeadlineFence::starting_at(start)?;
    let deadlines = PackageCleanupDeadlines::within_generation(fence, start)?;
    let mut operations = PackageCleanupTestOperations {
        normal_completion: PackageCompletionObservation::RetainedUnrecoverable,
        recovery_request: PackageRecoveryRequestObservation::Sent,
        recovery_request_state: PackageRecoveryRequestState::Available,
        underlying_recovery_requests: 0,
        coordinator_state: PackageExactCoordinatorStateObservation::Stopped,
        healthy_lifecycle: PackageHealthyLifecycleObservation {
            completion_ready: false,
            coordinator_reaped: false,
        },
        healthy_lifecycle_failure: None,
        events: Vec::new(),
    };
    let initial = PackageGenerationCleanupEvidence::default();

    assert_eq!(
        drive_package_generation_cleanup(&mut operations, initial, deadlines),
        Err(PackageCleanupFailure::RetainedUnrecoverable)
    );
    assert_eq!(
        operations.events,
        vec![PackageCleanupTestEvent::NormalCompletionPoll]
    );
    assert_eq!(
        initial.scratch_decision(),
        PackageScratchCleanupDecision::Retain
    );
    Ok(())
}

#[test]
fn package_cleanup_rejected_completion_never_consumes_recovery_or_waits_healthy_grace()
-> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fence = PackageGenerationDeadlineFence::starting_at(start)?;
    let deadlines = PackageCleanupDeadlines::within_generation(fence, start)?;
    let mut operations = PackageCleanupTestOperations {
        normal_completion: PackageCompletionObservation::Rejected,
        recovery_request: PackageRecoveryRequestObservation::Sent,
        recovery_request_state: PackageRecoveryRequestState::Available,
        underlying_recovery_requests: 0,
        coordinator_state: PackageExactCoordinatorStateObservation::Reaped,
        healthy_lifecycle: PackageHealthyLifecycleObservation {
            completion_ready: false,
            coordinator_reaped: true,
        },
        healthy_lifecycle_failure: None,
        events: Vec::new(),
    };

    assert_eq!(
        drive_package_generation_cleanup(
            &mut operations,
            PackageGenerationCleanupEvidence::default(),
            deadlines,
        ),
        Err(PackageCleanupFailure::CompletionBoundary)
    );
    assert_eq!(
        operations.events,
        vec![PackageCleanupTestEvent::NormalCompletionPoll]
    );
    assert_eq!(operations.underlying_recovery_requests, 0);
    assert_eq!(
        operations.recovery_request_state,
        PackageRecoveryRequestState::Available
    );
    Ok(())
}

#[test]
fn package_cleanup_normal_completion_skips_request_and_still_observes_exact_child()
-> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fence = PackageGenerationDeadlineFence::starting_at(start)?;
    let deadlines = PackageCleanupDeadlines::within_generation(fence, start)?;
    let mut operations = PackageCleanupTestOperations {
        normal_completion: PackageCompletionObservation::Verified,
        recovery_request: PackageRecoveryRequestObservation::Sent,
        recovery_request_state: PackageRecoveryRequestState::Available,
        underlying_recovery_requests: 0,
        coordinator_state: PackageExactCoordinatorStateObservation::NotProvenStopped,
        healthy_lifecycle: PackageHealthyLifecycleObservation {
            completion_ready: true,
            coordinator_reaped: true,
        },
        healthy_lifecycle_failure: None,
        events: Vec::new(),
    };

    drive_package_generation_cleanup(
        &mut operations,
        PackageGenerationCleanupEvidence::default(),
        deadlines,
    )?;

    assert_eq!(
        operations.events,
        vec![
            PackageCleanupTestEvent::NormalCompletionPoll,
            PackageCleanupTestEvent::ObserveExactCoordinatorState,
            PackageCleanupTestEvent::HealthyLifecycleGrace {
                completion_ready: true,
                coordinator_reaped: false,
            },
            PackageCleanupTestEvent::CompletionProof,
            PackageCleanupTestEvent::ReportedGroupsProof,
            PackageCleanupTestEvent::RuntimeProof,
        ]
    );
    Ok(())
}

#[test]
fn package_retained_outcome_during_healthy_grace_prevents_exact_child_fallback_and_proofs()
-> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fence = PackageGenerationDeadlineFence::starting_at(start)?;
    let deadlines = PackageCleanupDeadlines::within_generation(fence, start)?;
    let mut operations = PackageCleanupTestOperations {
        normal_completion: PackageCompletionObservation::Pending,
        recovery_request: PackageRecoveryRequestObservation::Sent,
        recovery_request_state: PackageRecoveryRequestState::Available,
        underlying_recovery_requests: 0,
        coordinator_state: PackageExactCoordinatorStateObservation::NotProvenStopped,
        healthy_lifecycle: PackageHealthyLifecycleObservation {
            completion_ready: false,
            coordinator_reaped: false,
        },
        healthy_lifecycle_failure: Some(PackageCleanupFailure::RetainedUnrecoverable),
        events: Vec::new(),
    };

    assert_eq!(
        drive_package_generation_cleanup(
            &mut operations,
            PackageGenerationCleanupEvidence::default(),
            deadlines,
        ),
        Err(PackageCleanupFailure::RetainedUnrecoverable)
    );
    assert_eq!(
        operations.events,
        vec![
            PackageCleanupTestEvent::NormalCompletionPoll,
            PackageCleanupTestEvent::RecoveryRequest,
            PackageCleanupTestEvent::ObserveExactCoordinatorState,
            PackageCleanupTestEvent::HealthyLifecycleGrace {
                completion_ready: false,
                coordinator_reaped: false,
            },
        ]
    );
    Ok(())
}

#[test]
fn package_cleanup_wake_requires_one_exact_stopped_coordinator_snapshot() {
    let stopped = package_process_state_for_test(101, b'T');
    assert_eq!(
        classify_exact_coordinator_snapshot(101, 501, &[stopped]),
        PackageExactCoordinatorStateObservation::Stopped
    );

    let mut active = stopped;
    active.state = b'S';
    assert_eq!(
        classify_exact_coordinator_snapshot(101, 501, &[active]),
        PackageExactCoordinatorStateObservation::NotProvenStopped
    );
    let mut wrong_group = stopped;
    wrong_group.process_group = 202;
    assert_eq!(
        classify_exact_coordinator_snapshot(101, 501, &[wrong_group]),
        PackageExactCoordinatorStateObservation::NotProvenStopped
    );
    let mut wrong_user = stopped;
    wrong_user.user = 502;
    assert_eq!(
        classify_exact_coordinator_snapshot(101, 501, &[wrong_user]),
        PackageExactCoordinatorStateObservation::NotProvenStopped
    );
    assert_eq!(
        classify_exact_coordinator_snapshot(101, 501, &[]),
        PackageExactCoordinatorStateObservation::NotProvenStopped
    );
    assert_eq!(
        classify_exact_coordinator_snapshot(101, 501, &[stopped, stopped]),
        PackageExactCoordinatorStateObservation::NotProvenStopped
    );
}

#[test]
fn package_cleanup_budget_is_monotonic_and_below_the_external_hard_timeout()
-> Result<(), Box<dyn Error>> {
    let origin = Instant::now();
    let initial = PackageGenerationDeadlineFence::starting_at(origin)?;
    let guardian_arm_observed = origin
        .checked_add(Duration::from_secs(1))
        .ok_or("Guardian arm observation overflowed")?;
    let fence = initial.after_guardian_startup_armed(guardian_arm_observed)?;
    let cleanup_start = fence.recovery_start;
    let guardian_startup_deadline = guardian_arm_observed
        .checked_add(PACKAGE_SUPERVISOR_STARTUP_TIMEOUT)
        .ok_or("Guardian startup deadline overflowed")?;
    assert_eq!(
        cleanup_start,
        guardian_startup_deadline
            .checked_add(PACKAGE_PARENT_STARTUP_HANDOFF_MARGIN)
            .ok_or("post-arm handoff boundary overflowed")?,
        "the parent recovery boundary was not anchored after the observed Guardian arm"
    );
    assert_eq!(
        fence.cleanup_budget.startup_handoff_margin,
        PACKAGE_PARENT_STARTUP_HANDOFF_MARGIN
    );
    assert_eq!(
        cleanup_start.duration_since(guardian_startup_deadline),
        PACKAGE_PARENT_STARTUP_HANDOFF_MARGIN,
        "the explicit post-arm handoff/report margin disappeared"
    );
    let latest_arm_observation = initial.guardian_startup_arm_observation_deadline()?;
    assert!(
        initial
            .after_guardian_startup_armed(latest_arm_observation)
            .is_ok(),
        "the last arm observation that preserves cleanup reserve was rejected"
    );
    let too_late = latest_arm_observation
        .checked_add(Duration::from_nanos(1))
        .ok_or("late arm observation overflowed")?;
    assert_eq!(
        initial.after_guardian_startup_armed(too_late),
        Err(PackageCleanupFailure::Deadline)
    );
    let deadlines = PackageCleanupDeadlines::within_generation(fence, cleanup_start)?;
    assert_eq!(
        PACKAGE_CLEANUP_HEALTHY_LIFECYCLE_GRACE,
        PACKAGE_SUPERVISOR_STARTUP_TIMEOUT
            .checked_add(PACKAGE_CLEANUP_STARTUP_RECOVERY_MARGIN)
            .ok_or("startup recovery grace overflowed")?
    );
    assert!(
        PACKAGE_SESSION_BACKEND_TIMEOUT
            >= PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT
                .checked_add(PACKAGE_SESSION_BACKEND_START_MARGIN)
                .ok_or("backend lifetime budget overflowed")?
    );
    assert_eq!(
        deadlines.normal_completion,
        cleanup_start
            .checked_add(PACKAGE_CLEANUP_NORMAL_COMPLETION_RACE)
            .ok_or("normal completion deadline overflowed")?
    );
    assert_eq!(
        deadlines.recovery_request,
        deadlines
            .normal_completion
            .checked_add(PACKAGE_CLEANUP_RECOVERY_REQUEST_TIMEOUT)
            .ok_or("recovery request deadline overflowed")?
    );
    assert_eq!(
        deadlines.healthy_lifecycle,
        deadlines
            .recovery_request
            .checked_add(PACKAGE_CLEANUP_HEALTHY_LIFECYCLE_GRACE)
            .ok_or("healthy lifecycle deadline overflowed")?
    );
    assert_eq!(
        deadlines.coordinator_term,
        deadlines
            .healthy_lifecycle
            .checked_add(PACKAGE_CLEANUP_COORDINATOR_TERM_GRACE)
            .ok_or("coordinator term deadline overflowed")?
    );
    assert_eq!(
        deadlines.coordinator_kill,
        deadlines
            .coordinator_term
            .checked_add(PACKAGE_CLEANUP_COORDINATOR_KILL_WAIT)
            .ok_or("coordinator kill deadline overflowed")?
    );
    assert_eq!(
        deadlines.completion_proof,
        deadlines
            .coordinator_kill
            .checked_add(PACKAGE_CLEANUP_COMPLETION_PROOF_TIMEOUT)
            .ok_or("completion proof deadline overflowed")?
    );
    assert_eq!(
        deadlines.reported_groups_proof,
        deadlines
            .completion_proof
            .checked_add(PACKAGE_CLEANUP_GROUP_PROOF_TIMEOUT)
            .ok_or("reported groups deadline overflowed")?
    );
    let cleanup_with_margin = deadlines
        .reported_groups_proof
        .checked_add(PACKAGE_CLEANUP_EXTERNAL_OBSERVATION_MARGIN)
        .ok_or("cleanup observation margin overflowed")?;
    assert!(cleanup_with_margin < fence.external_fence);
    assert!(deadlines.reported_groups_proof <= fence.cleanup_fence);
    Ok(())
}

#[test]
fn deterministic_package_cleanup_budget_is_short_bounded_and_target_specific()
-> Result<(), Box<dyn Error>> {
    let origin = Instant::now();
    let official = PackageGenerationDeadlineFence::starting_at_for_target(
        origin,
        PackageProviderTarget::Official,
    )?;
    let deterministic = PackageGenerationDeadlineFence::starting_at_for_target(
        origin,
        PackageProviderTarget::DeterministicFixture,
    )?;

    assert_eq!(
        deterministic.recovery_start,
        origin
            .checked_add(PACKAGE_DETERMINISTIC_SUPERVISOR_TIMEOUT)
            .ok_or("deterministic recovery start overflowed")?
    );
    assert_eq!(
        deterministic.cleanup_budget.startup_handoff_margin,
        Duration::ZERO,
        "the deterministic target must keep its existing fixed recovery fence"
    );
    assert_eq!(
        deterministic.external_fence,
        origin
            .checked_add(PACKAGE_DETERMINISTIC_EXTERNAL_HARD_TIMEOUT)
            .ok_or("deterministic external fence overflowed")?
    );
    assert_eq!(
        deterministic.external_fence,
        origin
            .checked_add(Duration::from_secs(105))
            .ok_or("expected deterministic external fence overflowed")?
    );
    assert!(deterministic.recovery_start < official.recovery_start);
    assert!(deterministic.external_fence < official.external_fence);

    let deadlines =
        PackageCleanupDeadlines::within_generation(deterministic, deterministic.recovery_start)?;
    assert_eq!(
        deadlines.healthy_lifecycle,
        deadlines
            .recovery_request
            .checked_add(PACKAGE_DETERMINISTIC_CLEANUP_HEALTHY_LIFECYCLE_GRACE)
            .ok_or("deterministic healthy lifecycle deadline overflowed")?
    );
    assert_eq!(
        deadlines.reported_groups_proof,
        deadlines
            .completion_proof
            .checked_add(PACKAGE_DETERMINISTIC_CLEANUP_GROUP_PROOF_TIMEOUT)
            .ok_or("deterministic group proof deadline overflowed")?
    );
    assert!(
        deadlines
            .reported_groups_proof
            .checked_add(PACKAGE_DETERMINISTIC_CLEANUP_EXTERNAL_OBSERVATION_MARGIN)
            .ok_or("deterministic observation margin overflowed")?
            < deterministic.external_fence
    );
    Ok(())
}

#[test]
fn unproven_package_cleanup_exits_with_a_fixed_diagnostic_instead_of_hanging_ci()
-> Result<(), Box<dyn Error>> {
    if std::env::var_os(PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER_ENV)
        .is_some_and(|mode| mode == PACKAGE_UNPROVEN_CLEANUP_PARK_HELPER_MODE)
    {
        {
            let mut stderr = io::stderr().lock();
            if writeln!(stderr, "{PACKAGE_UNPROVEN_CLEANUP_PARK_READY}")
                .and_then(|()| stderr.flush())
                .is_err()
            {
                calcifer_unix_child_fd::exit_process_without_destructors(
                    PACKAGE_UNPROVEN_CLEANUP_EXIT_CODE,
                );
            }
        }
        loop {
            thread::park();
        }
    }
    if std::env::var_os(PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER_ENV).is_some_and(|mode| {
        mode == PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER_MODE
            || mode == PACKAGE_UNPROVEN_CLEANUP_CAUSAL_EXIT_HELPER_MODE
    }) {
        let causal = std::env::var_os(PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER_ENV)
            .is_some_and(|mode| mode == PACKAGE_UNPROVEN_CLEANUP_CAUSAL_EXIT_HELPER_MODE);
        let (_output_sender, output_result) = mpsc::sync_channel(1);
        let mut harness = OfficialTuiPackageHarness {
            _provider_suite_budget: PackageProviderSuiteBudget::Deterministic {
                _lease: PackageDeterministicSuiteLease {
                    started: Instant::now(),
                    reservation: None,
                },
            },
            scratch: None,
            backend: None,
            coordinator: None,
            completion: None,
            provider_target: PackageProviderTarget::DeterministicFixture,
            startup_fault: None,
            inference_expectation: PackageInferenceExpectation::Zero,
            recovery_checkpoint: None,
            recovery_request_state: PackageRecoveryRequestState::Available,
            generation_cleanup: None,
            generation_deadline_fence: None,
            guardian_startup_arm_observed: false,
            master: None,
            initial_termios: None,
            output_cancel: None,
            output_result,
            startup_sentinel_observed: None,
            response_sentinel_observed: None,
            output_worker: None,
            output_finished: true,
            last_handoff_probe_phase: None,
            recovery_failure_evidence: PackageRecoveryFailureEvidence::default(),
            last_fixed_failure_detail: None,
            last_fixed_cleanup_failure_detail: None,
        };
        if causal {
            harness
                .recovery_failure_evidence
                .snapshot_error(&PackageRecoveryDriveFailure::InitialGate);
            harness
                .recovery_failure_evidence
                .snapshot_secondary(Some(PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0]));
        }
        harness.fail_closed_unproven_generation_cleanup();
    }

    let parked = run_bounded_unproven_cleanup_child(
        PACKAGE_UNPROVEN_CLEANUP_PARK_HELPER_MODE,
        Duration::from_millis(100),
    )?;
    assert!(parked.timed_out, "the parked helper escaped its test bound");
    assert_eq!(
        parked.status.signal(),
        Some(rustix::process::Signal::KILL.as_raw()),
        "the parked helper was not exactly killed and reaped"
    );
    assert!(
        parked
            .diagnostic
            .contains(PACKAGE_UNPROVEN_CLEANUP_PARK_READY)
    );

    let output = run_bounded_unproven_cleanup_child(
        PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER_MODE,
        PACKAGE_UNPROVEN_CLEANUP_CHILD_TIMEOUT,
    )?;
    assert!(!output.timed_out, "unproven package cleanup did not exit");
    assert_eq!(
        output.status.code(),
        Some(i32::from(PACKAGE_UNPROVEN_CLEANUP_EXIT_CODE)),
        "unproven package cleanup did not exit with its fixed status"
    );
    assert_eq!(output.status.signal(), None);
    assert!(output.diagnostic.contains(concat!(
        "package-generation-cleanup-unproven:",
        "phase=scratch-missing,failure=unclassified,secondary=none"
    )));
    assert!(
        !output
            .diagnostic
            .contains(std::env::current_dir()?.to_string_lossy().as_ref())
    );

    let causal = run_bounded_unproven_cleanup_child(
        PACKAGE_UNPROVEN_CLEANUP_CAUSAL_EXIT_HELPER_MODE,
        PACKAGE_UNPROVEN_CLEANUP_CHILD_TIMEOUT,
    )?;
    assert!(!causal.timed_out, "causal unproven cleanup did not exit");
    assert_eq!(
        causal.status.code(),
        Some(i32::from(PACKAGE_UNPROVEN_CLEANUP_EXIT_CODE))
    );
    assert_eq!(causal.status.signal(), None);
    assert!(causal.diagnostic.contains(&format!(
        concat!(
            "package-generation-cleanup-unproven:",
            "phase=scratch-missing,failure={},secondary={}"
        ),
        PackageRecoveryDriveFailure::InitialGate.marker(),
        PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0]
    )));
    assert!(!causal.diagnostic.contains("private provider payload"));
    assert!(!causal.diagnostic.contains("credential"));
    assert!(
        !causal
            .diagnostic
            .contains(std::env::current_dir()?.to_string_lossy().as_ref())
    );
    Ok(())
}

struct BoundedUnprovenCleanupChild {
    status: std::process::ExitStatus,
    timed_out: bool,
    diagnostic: String,
}

fn run_bounded_unproven_cleanup_child(
    mode: &str,
    timeout: Duration,
) -> Result<BoundedUnprovenCleanupChild, Box<dyn Error>> {
    let mut diagnostic_capture = create_unlinked_unproven_cleanup_capture()?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "providers::codex::supervisor::packaged_smoke::unproven_package_cleanup_exits_with_a_fixed_diagnostic_instead_of_hanging_ci",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PACKAGE_UNPROVEN_CLEANUP_EXIT_HELPER_ENV, mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(diagnostic_capture.try_clone()?));
    let mut child = command.spawn()?;
    drop(command);
    let mut early_status = None;
    if mode == PACKAGE_UNPROVEN_CLEANUP_PARK_HELPER_MODE {
        let readiness_deadline = Instant::now()
            .checked_add(PACKAGE_UNPROVEN_CLEANUP_CHILD_TIMEOUT)
            .ok_or("unproven cleanup helper readiness deadline overflowed")?;
        loop {
            if diagnostic_capture.metadata()?.len() != 0 {
                break;
            }
            if let Some(status) = child.try_wait()? {
                early_status = Some(status);
                break;
            }
            if Instant::now() >= readiness_deadline {
                let _ = kill_and_reap_unproven_cleanup_child(&mut child)?;
                return Err("parked unproven cleanup helper never published readiness".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("unproven cleanup child deadline overflowed")?;
    let (status, timed_out) = if let Some(status) = early_status {
        (status, false)
    } else {
        loop {
            if let Some(status) = child.try_wait()? {
                break (status, false);
            }
            if Instant::now() >= deadline {
                let status = kill_and_reap_unproven_cleanup_child(&mut child)?;
                break (status, true);
            }
            thread::sleep(Duration::from_millis(10));
        }
    };

    let length = diagnostic_capture.metadata()?.len();
    if length > PACKAGE_UNPROVEN_CLEANUP_DIAGNOSTIC_LIMIT {
        return Err("unproven cleanup diagnostic exceeded its fixed bound".into());
    }
    diagnostic_capture.seek(SeekFrom::Start(0))?;
    let mut diagnostic = Vec::with_capacity(usize::try_from(length)?);
    diagnostic_capture
        .take(PACKAGE_UNPROVEN_CLEANUP_DIAGNOSTIC_LIMIT + 1)
        .read_to_end(&mut diagnostic)?;
    if u64::try_from(diagnostic.len())? > PACKAGE_UNPROVEN_CLEANUP_DIAGNOSTIC_LIMIT {
        return Err("unproven cleanup diagnostic exceeded its fixed bound".into());
    }

    Ok(BoundedUnprovenCleanupChild {
        status,
        timed_out,
        diagnostic: String::from_utf8(diagnostic)?,
    })
}

fn kill_and_reap_unproven_cleanup_child(
    child: &mut Child,
) -> Result<std::process::ExitStatus, Box<dyn Error>> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    match child.kill() {
        Ok(()) => {
            wait_for_package_child(child, Instant::now() + PACKAGE_UNPROVEN_CLEANUP_KILL_WAIT)
        }
        Err(error) => match child.try_wait()? {
            Some(status) => Ok(status),
            None => Err(error.into()),
        },
    }
}

fn create_unlinked_unproven_cleanup_capture() -> Result<File, Box<dyn Error>> {
    let parent = fs::canonicalize("/tmp")?;
    for _ in 0..PACKAGE_SCRATCH_CREATE_ATTEMPTS {
        let path = parent.join(format!(
            "calcifer-unproven-cleanup-{}.stderr",
            Uuid::new_v4().simple()
        ));
        let capture = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(capture) => capture,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let metadata = capture.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != 0
        {
            fs::remove_file(path)?;
            return Err("unproven cleanup diagnostic capture was not private".into());
        }
        fs::remove_file(path)?;
        return Ok(capture);
    }
    Err("unproven cleanup diagnostic capture nonce attempts were exhausted".into())
}

#[test]
fn package_operation_deadline_is_global_and_preserves_full_recovery_budget_under_drip_progress()
-> Result<(), Box<dyn Error>> {
    let origin = Instant::now();
    let fence = PackageGenerationDeadlineFence::starting_at(origin)?;
    let recovery_start = origin
        .checked_add(PACKAGE_SUPERVISOR_STARTUP_TIMEOUT)
        .and_then(|deadline| deadline.checked_add(PACKAGE_PARENT_STARTUP_HANDOFF_MARGIN))
        .ok_or("package recovery start overflowed")?;
    let ordinary_startup_deadline = origin
        .checked_add(PACKAGE_SUPERVISOR_STARTUP_TIMEOUT)
        .ok_or("ordinary startup deadline overflowed")?;

    assert_eq!(fence.recovery_start, recovery_start);
    assert_eq!(
        fence.exercise_deadline(origin, IO_TIMEOUT)?,
        origin
            .checked_add(IO_TIMEOUT)
            .ok_or("short package exercise deadline overflowed")?
    );
    assert_eq!(
        fence.exercise_deadline(origin, PACKAGE_SUPERVISOR_STARTUP_TIMEOUT)?,
        ordinary_startup_deadline,
        "ordinary phase deadlines must not silently inherit the parent handoff margin"
    );
    assert_eq!(fence.recovery_checkpoint_deadline(origin)?, recovery_start);

    // Progress just before the global fence must not manufacture another
    // per-phase 600 second window.
    let drip_progress = recovery_start
        .checked_sub(Duration::from_millis(1))
        .ok_or("drip progress underflowed")?;
    assert_eq!(
        fence.recovery_checkpoint_deadline(drip_progress)?,
        recovery_start
    );
    assert_eq!(
        fence.recovery_checkpoint_deadline(recovery_start),
        Err(PackageCleanupFailure::Deadline)
    );

    let cleanup = PackageCleanupDeadlines::within_generation(fence, recovery_start)?;
    let cleanup_with_margin = cleanup
        .reported_groups_proof
        .checked_add(PACKAGE_CLEANUP_EXTERNAL_OBSERVATION_MARGIN)
        .ok_or("cleanup observation margin overflowed")?;
    assert!(cleanup_with_margin < fence.external_fence);
    assert!(cleanup.reported_groups_proof <= fence.cleanup_fence);
    Ok(())
}

#[test]
fn package_cleanup_deadlines_cap_at_the_recorded_generation_fence_and_reject_overflow()
-> Result<(), Box<dyn Error>> {
    let origin = Instant::now();
    let fence = PackageGenerationDeadlineFence::starting_at(origin)?;
    let late_cleanup = fence
        .cleanup_fence
        .checked_sub(Duration::from_millis(1))
        .ok_or("late cleanup start underflowed")?;
    let deadlines = PackageCleanupDeadlines::within_generation(fence, late_cleanup)?;
    assert_eq!(deadlines.normal_completion, fence.cleanup_fence);
    assert_eq!(deadlines.recovery_request, fence.cleanup_fence);
    assert_eq!(deadlines.healthy_lifecycle, fence.cleanup_fence);
    assert_eq!(deadlines.coordinator_term, fence.cleanup_fence);
    assert_eq!(deadlines.coordinator_kill, fence.cleanup_fence);
    assert_eq!(deadlines.completion_proof, fence.cleanup_fence);
    assert_eq!(deadlines.reported_groups_proof, fence.cleanup_fence);
    assert_eq!(
        PackageGenerationDeadlineFence::starting_at_with_timeout(origin, Duration::MAX),
        Err(PackageCleanupFailure::Deadline)
    );
    let mut overflow = PackageCleanupBudget::for_target(PackageProviderTarget::Official);
    overflow.startup = Duration::MAX;
    overflow.startup_handoff_margin = Duration::from_nanos(1);
    assert_eq!(
        PackageGenerationDeadlineFence::starting_at_with_budget(origin, overflow),
        Err(PackageCleanupFailure::Deadline)
    );
    Ok(())
}

#[test]
fn package_child_markers_are_observation_only_and_never_signal_targets() {
    let source = include_str!("packaged_smoke.rs");
    assert!(!source.contains(&["kill_process", "_group"].concat()));
    assert!(!source.contains(&["fn signal_", "package_process"].concat()));
    assert!(!source.contains(&["terminate_reported_", "package_processes"].concat()));
    assert!(source.contains("Pid::from_child"));
}

#[test]
fn package_child_marker_is_not_visible_before_its_complete_payload_is_durable()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let marker = report.join("tui.child");
    let publisher_marker = marker.clone();
    let staged = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let publisher_staged = Arc::clone(&staged);
    let publisher_release = Arc::clone(&release);
    let publisher = thread::spawn(move || {
        write_private_atomic_new_with_before_publish(&publisher_marker, b"30501 30501\n", || {
            publisher_staged.wait();
            publisher_release.wait();
            Ok(())
        })
        .map_err(|error| error.to_string())
    });

    staged.wait();
    let visible_before_publish = fs::symlink_metadata(&marker).is_ok();
    release.wait();
    publisher
        .join()
        .map_err(|_| io::Error::other("package child marker publisher panicked"))?
        .map_err(io::Error::other)?;

    let payload = read_private_bounded(&marker, 64)?;
    let metadata = fs::symlink_metadata(&marker)?;
    let replacement_rejected = write_private_atomic_new(&marker, b"99999 99999\n").is_err();
    let preserved_payload = read_private_bounded(&marker, 64)?;
    scratch.cleanup()?;

    assert!(
        !visible_before_publish,
        "a package child marker became visible before publication"
    );
    assert_eq!(payload, b"30501 30501\n");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(replacement_rejected);
    assert_eq!(preserved_payload, b"30501 30501\n");
    Ok(())
}

#[test]
fn package_session_observation_is_invisible_until_complete_json_is_durable()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let marker = report.join("session-observation.json");
    let observation = PackagedSessionObservation {
        initial_size: Some((37, 111)),
        input: b"complete-observation".to_vec(),
        output_sentinel_seen: true,
        shutdown_observed: true,
        ..PackagedSessionObservation::default()
    };
    let publisher_report = report.clone();
    let publisher_observation = observation.clone();
    let staged = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let publisher_staged = Arc::clone(&staged);
    let publisher_release = Arc::clone(&release);
    let publisher = thread::spawn(move || {
        write_package_session_observation_with_before_publish(
            &publisher_report,
            &publisher_observation,
            || {
                publisher_staged.wait();
                publisher_release.wait();
                Ok(())
            },
        )
        .map_err(|error| error.to_string())
    });

    staged.wait();
    let before_publish = require_rejected_test_result(
        read_private_bounded(&marker, 128 * 1024),
        "session observation became visible before atomic publication",
    )?;
    release.wait();
    publisher
        .join()
        .map_err(|_| io::Error::other("package session observation publisher panicked"))?
        .map_err(io::Error::other)?;

    assert_eq!(before_publish.kind(), io::ErrorKind::NotFound);
    let payload = read_private_bounded(&marker, 128 * 1024)?;
    let decoded: PackagedSessionObservation = serde_json::from_slice(&payload)?;
    assert_eq!(decoded, observation);
    scratch.cleanup()?;
    Ok(())
}

#[test]
fn package_child_marker_publication_and_reader_fail_closed_for_unsafe_nodes_and_payloads()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;

    let safe_marker = report.join("safe.child");
    write_private_atomic_new(&safe_marker, b"30501 30501\n")?;

    let symlink_marker = report.join("symlink.child");
    std::os::unix::fs::symlink(&safe_marker, &symlink_marker)?;
    let symlink_rejected = write_private_atomic_new(&symlink_marker, b"99999 99999\n").is_err();
    let symlink_preserved = fs::symlink_metadata(&symlink_marker)?
        .file_type()
        .is_symlink();

    let wrong_mode_marker = report.join("wrong-mode.child");
    write_private_new(&wrong_mode_marker, b"unsafe\n")?;
    fs::set_permissions(&wrong_mode_marker, fs::Permissions::from_mode(0o640))?;
    let wrong_mode_rejected =
        write_private_atomic_new(&wrong_mode_marker, b"99999 99999\n").is_err();
    let wrong_mode_preserved = fs::read(&wrong_mode_marker)? == b"unsafe\n"
        && fs::symlink_metadata(&wrong_mode_marker)?
            .permissions()
            .mode()
            & 0o7777
            == 0o640;

    let link_source = report.join("link-source");
    let multi_link_marker = report.join("multi-link.child");
    write_private_new(&link_source, b"linked\n")?;
    fs::hard_link(&link_source, &multi_link_marker)?;
    let multi_link_rejected =
        write_private_atomic_new(&multi_link_marker, b"99999 99999\n").is_err();
    let link_source_metadata = fs::symlink_metadata(&link_source)?;
    let multi_link_metadata = fs::symlink_metadata(&multi_link_marker)?;
    let multi_link_preserved = link_source_metadata.dev() == multi_link_metadata.dev()
        && link_source_metadata.ino() == multi_link_metadata.ino()
        && multi_link_metadata.nlink() == 2;

    let malformed_marker = report.join("malformed.child");
    write_private_atomic_new(&malformed_marker, b"30501\n")?;
    let malformed_rejected = wait_for_package_child_marker(
        &malformed_marker,
        Instant::now() + Duration::from_millis(50),
    )
    .is_err();

    scratch.cleanup()?;
    assert!(symlink_rejected);
    assert!(symlink_preserved);
    assert!(wrong_mode_rejected);
    assert!(wrong_mode_preserved);
    assert!(multi_link_rejected);
    assert!(multi_link_preserved);
    assert!(malformed_rejected);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageInferenceExpectation {
    Zero,
    ExactlyOne,
}

impl PackageInferenceExpectation {
    const fn for_fixture_checkpoint(checkpoint: RecoveryCheckpoint) -> Self {
        match checkpoint {
            RecoveryCheckpoint::StartupQueued
            | RecoveryCheckpoint::Ready
            | RecoveryCheckpoint::Active
            | RecoveryCheckpoint::Suspended => Self::Zero,
            RecoveryCheckpoint::RetainedQuiescing
            | RecoveryCheckpoint::RetainedRestorePending
            | RecoveryCheckpoint::RetainedCleanupPending => Self::ExactlyOne,
        }
    }
}

struct OfficialTuiPackageHarness {
    _provider_suite_budget: PackageProviderSuiteBudget,
    scratch: Option<PackageScratch>,
    backend: Option<PackageSessionBackend>,
    coordinator: Option<Child>,
    completion: Option<AnchorCompletion>,
    provider_target: PackageProviderTarget,
    startup_fault: Option<PackageStartupFault>,
    inference_expectation: PackageInferenceExpectation,
    recovery_checkpoint: Option<RecoveryCheckpoint>,
    recovery_request_state: PackageRecoveryRequestState,
    generation_cleanup: Option<PackageGenerationCleanupEvidence>,
    generation_deadline_fence: Option<PackageGenerationDeadlineFence>,
    guardian_startup_arm_observed: bool,
    master: Option<PtyMaster>,
    initial_termios: Option<rustix::termios::Termios>,
    output_cancel: Option<SyncSender<()>>,
    output_result: Receiver<Result<PackageOutputDrain, String>>,
    startup_sentinel_observed: Option<Receiver<()>>,
    response_sentinel_observed: Option<Receiver<()>>,
    output_worker: Option<JoinHandle<()>>,
    output_finished: bool,
    last_handoff_probe_phase: Option<PackageHandoffProbePhase>,
    recovery_failure_evidence: PackageRecoveryFailureEvidence,
    last_fixed_failure_detail: Option<&'static str>,
    last_fixed_cleanup_failure_detail: Option<&'static str>,
}

#[derive(Debug)]
struct PackageHarnessCleanupFailure {
    phase: &'static str,
    source: Box<dyn Error>,
}

#[derive(Debug, Default)]
struct PackageHarnessCleanupFailures {
    failures: Vec<PackageHarnessCleanupFailure>,
}

impl PackageHarnessCleanupFailures {
    fn record(&mut self, phase: &'static str, source: Box<dyn Error>) {
        self.failures
            .push(PackageHarnessCleanupFailure { phase, source });
    }

    fn record_result(&mut self, phase: &'static str, result: Result<(), Box<dyn Error>>) {
        if let Err(error) = result {
            self.record(phase, error);
        }
    }

    fn finish(self) -> Result<(), Box<dyn Error>> {
        if self.failures.is_empty() {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}

impl fmt::Display for PackageHarnessCleanupFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("package harness cleanup failed")?;
        for failure in &self.failures {
            write!(formatter, "; {}: {}", failure.phase, failure.source)?;
        }
        Ok(())
    }
}

impl Error for PackageHarnessCleanupFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.failures.first().map(|failure| failure.source.as_ref())
    }
}

struct PreservedPackageEvidence {
    scratch: PackageScratch,
}

impl PreservedPackageEvidence {
    fn new(scratch: PackageScratch) -> Result<Self, Box<dyn Error>> {
        scratch.validate_owned_root()?;
        Ok(Self { scratch })
    }

    fn root(&self) -> &Path {
        &self.scratch.root
    }

    fn cleanup(self) -> Result<(), Box<dyn Error>> {
        self.scratch.cleanup()
    }
}

enum PackageScratchDisposition {
    Deleted,
    Preserved(PreservedPackageEvidence),
    Unavailable,
}

struct PackageHarnessCleanupOutcome {
    result: Result<(), Box<dyn Error>>,
    scratch: PackageScratchDisposition,
}

impl PackageHarnessCleanupOutcome {
    fn preserved_evidence_root(&self) -> Option<&Path> {
        match &self.scratch {
            PackageScratchDisposition::Preserved(evidence) => Some(evidence.root()),
            PackageScratchDisposition::Deleted | PackageScratchDisposition::Unavailable => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageHarnessSetupPhase {
    Filesystem,
    RuntimeParentValidation,
    PtyOpen,
    CommandBuild,
    PtyConfiguration,
    OutputWorker,
    CompletionAuthority,
    GenerationFence,
    CoordinatorSpawn,
    InitialPtyWrite,
}

impl PackageHarnessSetupPhase {
    const fn fixed_label(self) -> &'static str {
        match self {
            Self::Filesystem => "package-setup.filesystem",
            Self::RuntimeParentValidation => "package-setup.runtime-parent-validation",
            Self::PtyOpen => "package-setup.pty-open",
            Self::CommandBuild => "package-setup.command-build",
            Self::PtyConfiguration => "package-setup.pty-configuration",
            Self::OutputWorker => "package-setup.output-worker",
            Self::CompletionAuthority => "package-setup.completion-authority",
            Self::GenerationFence => "package-setup.generation-fence",
            Self::CoordinatorSpawn => "package-setup.coordinator-spawn",
            Self::InitialPtyWrite => "package-setup.initial-pty-write",
        }
    }
}

struct PackageHarnessSetupFailure {
    setup_phase: PackageHarnessSetupPhase,
    generation_started: bool,
    cleanup_failed: bool,
    cleanup_phase: Option<&'static str>,
    preserved_evidence_root: Option<PathBuf>,
}

impl fmt::Debug for PackageHarnessSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageHarnessSetupFailure")
            .field("setup_phase", &self.setup_phase)
            .field("generation_started", &self.generation_started)
            .field("cleanup_failed", &self.cleanup_failed)
            .field("cleanup_phase", &self.cleanup_phase)
            .field("preserved_evidence_root", &self.preserved_evidence_root)
            .finish()
    }
}

impl fmt::Display for PackageHarnessSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "package harness setup failed at fixed phase {}",
            self.setup_phase.fixed_label()
        )?;
        if self.generation_started {
            formatter.write_str(" after generation start")?;
        }
        if self.cleanup_failed {
            formatter.write_str("; package cleanup failed")?;
            if let Some(phase) = self.cleanup_phase {
                write!(formatter, " at fixed cleanup phase {phase}")?;
            }
        }
        if let Some(root) = &self.preserved_evidence_root {
            write!(
                formatter,
                "; package evidence root preserved at {}",
                root.display()
            )?;
        }
        Ok(())
    }
}

impl Error for PackageHarnessSetupFailure {}

struct PackageExerciseCleanupFailure {
    exercise_failed: bool,
    cleanup_failed: bool,
    exercise_phase: Option<&'static str>,
    secondary_failure_detail: Option<&'static str>,
    cleanup_phase: Option<&'static str>,
    recovery_case: Option<&'static str>,
    handoff_probe_phase: Option<PackageHandoffProbePhase>,
    preserved_evidence_root: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageOperationFailureEvidence {
    primary: Option<&'static str>,
    secondary: Option<&'static str>,
}

impl PackageOperationFailureEvidence {
    const fn new(primary: Option<&'static str>, secondary: Option<&'static str>) -> Self {
        Self { primary, secondary }
    }

    const fn primary(primary: Option<&'static str>) -> Self {
        Self::new(primary, None)
    }
}

impl fmt::Debug for PackageExerciseCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageExerciseCleanupFailure")
            .field("exercise_failed", &self.exercise_failed)
            .field("cleanup_failed", &self.cleanup_failed)
            .field("exercise_phase", &self.exercise_phase)
            .field("secondary_failure_detail", &self.secondary_failure_detail)
            .field("cleanup_phase", &self.cleanup_phase)
            .field("recovery_case", &self.recovery_case)
            .field("handoff_probe_phase", &self.handoff_probe_phase)
            .field("preserved_evidence_root", &self.preserved_evidence_root)
            .finish()
    }
}

impl fmt::Display for PackageExerciseCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.exercise_failed, self.cleanup_failed) {
            (true, true) => formatter.write_str("package exercise failed; package cleanup failed"),
            (true, false) => formatter.write_str("package exercise failed"),
            (false, true) => formatter.write_str("package cleanup failed"),
            (false, false) => formatter.write_str("package operation failure was empty"),
        }?;
        if let Some(phase) = self.exercise_phase {
            write!(formatter, " at fixed phase {phase}")?;
        }
        if let Some(detail) = self.secondary_failure_detail {
            write!(formatter, "; fixed secondary failure {detail}")?;
        }
        if let Some(phase) = self.cleanup_phase {
            if self.exercise_phase.is_some() {
                write!(formatter, "; fixed cleanup phase {phase}")?;
            } else {
                write!(formatter, " at fixed cleanup phase {phase}")?;
            }
        }
        if let Some(recovery_case) = self.recovery_case {
            write!(formatter, "; fixed recovery case {recovery_case}")?;
        }
        if let Some(handoff_probe_phase) = self.handoff_probe_phase {
            write!(
                formatter,
                "; last fixed handoff probe phase {}",
                handoff_probe_phase.fixed_label()
            )?;
        }
        if let Some(root) = &self.preserved_evidence_root {
            write!(
                formatter,
                "; package evidence root preserved at {}",
                root.display()
            )?;
        }
        Ok(())
    }
}

impl Error for PackageExerciseCleanupFailure {}

fn combine_package_exercise_and_cleanup(
    exercise: Result<(), Box<dyn Error>>,
    cleanup: Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    combine_package_exercise_and_cleanup_at_phase(exercise, cleanup, None)
}

fn combine_package_exercise_and_cleanup_at_phase(
    exercise: Result<(), Box<dyn Error>>,
    cleanup: Result<(), Box<dyn Error>>,
    exercise_phase: Option<&'static str>,
) -> Result<(), Box<dyn Error>> {
    combine_package_exercise_and_cleanup_at_phases(exercise, cleanup, exercise_phase, None)
}

fn combine_package_exercise_and_cleanup_at_phases(
    exercise: Result<(), Box<dyn Error>>,
    cleanup: Result<(), Box<dyn Error>>,
    exercise_phase: Option<&'static str>,
    cleanup_phase: Option<&'static str>,
) -> Result<(), Box<dyn Error>> {
    combine_package_exercise_and_cleanup_with_diagnostics(
        exercise,
        cleanup,
        exercise_phase,
        cleanup_phase,
        None,
    )
}

fn combine_package_exercise_and_cleanup_at_recovery_case(
    exercise: Result<(), Box<dyn Error>>,
    cleanup: Result<(), Box<dyn Error>>,
    exercise_phase: Option<&'static str>,
    cleanup_phase: Option<&'static str>,
    recovery_case: &'static str,
) -> Result<(), Box<dyn Error>> {
    combine_package_exercise_and_cleanup_with_diagnostics(
        exercise,
        cleanup,
        exercise_phase,
        cleanup_phase,
        Some(recovery_case),
    )
}

fn combine_package_exercise_and_cleanup_with_diagnostics(
    exercise: Result<(), Box<dyn Error>>,
    cleanup: Result<(), Box<dyn Error>>,
    exercise_phase: Option<&'static str>,
    cleanup_phase: Option<&'static str>,
    recovery_case: Option<&'static str>,
) -> Result<(), Box<dyn Error>> {
    combine_package_exercise_and_cleanup_with_evidence(
        exercise,
        cleanup,
        PackageOperationFailureEvidence::primary(exercise_phase),
        cleanup_phase,
        recovery_case,
        None,
        None,
    )
}

fn combine_package_exercise_and_cleanup_with_evidence(
    exercise: Result<(), Box<dyn Error>>,
    cleanup: Result<(), Box<dyn Error>>,
    failure_evidence: PackageOperationFailureEvidence,
    cleanup_phase: Option<&'static str>,
    recovery_case: Option<&'static str>,
    handoff_probe_phase: Option<PackageHandoffProbePhase>,
    preserved_evidence_root: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    match (exercise, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (exercise, cleanup) => Err(Box::new(PackageExerciseCleanupFailure {
            exercise_failed: exercise.is_err(),
            cleanup_failed: cleanup.is_err(),
            exercise_phase: failure_evidence.primary,
            secondary_failure_detail: failure_evidence.secondary,
            cleanup_phase,
            recovery_case,
            handoff_probe_phase,
            preserved_evidence_root,
        })),
    }
}

fn package_operation_failure_can_finalize_during_cleanup(marker: &'static str) -> bool {
    PACKAGED_COMPATIBILITY_FAILURE_MARKERS.contains(&marker)
        || PACKAGED_APP_SOCKET_FAILURE_MARKERS.contains(&marker)
        || PACKAGED_SESSION_STARTUP_FAILURE_MARKERS.contains(&marker)
        || PACKAGE_JOB_CONTROL_FAILURE_MARKERS.contains(&marker)
        || PACKAGE_OFFICIAL_TUI_GROUP_FAILURE_MARKERS.contains(&marker)
        || PACKAGE_SESSION_OBSERVATION_FAILURE_MARKERS.contains(&marker)
        || PACKAGED_STARTUP_FAILURE_MARKERS.contains(&marker)
        || PACKAGE_SESSION_BACKEND_FAILURE_MARKERS.contains(&marker)
}

fn select_package_failure_phase(
    failure_before_cleanup: Option<&'static str>,
    phase_before_cleanup: Option<&'static str>,
    failure_during_cleanup: Option<&'static str>,
) -> Option<&'static str> {
    failure_before_cleanup
        .or_else(|| {
            failure_during_cleanup
                .filter(|marker| package_operation_failure_can_finalize_during_cleanup(marker))
        })
        .or(phase_before_cleanup)
}

#[test]
fn package_exercise_and_cleanup_failures_are_aggregated_with_fixed_redacted_labels()
-> Result<(), Box<dyn Error>> {
    let exercise: Result<(), Box<dyn Error>> = Err("private-exercise-detail".into());
    let cleanup: Result<(), Box<dyn Error>> = Err("private-cleanup-detail".into());
    let error = require_rejected_test_result(
        combine_package_exercise_and_cleanup(exercise, cleanup),
        "two failures unexpectedly succeeded",
    )?;
    assert_eq!(
        error.to_string(),
        "package exercise failed; package cleanup failed"
    );
    let debug = format!("{error:?}");
    assert!(!debug.contains("private-exercise-detail"));
    assert!(!debug.contains("private-cleanup-detail"));
    assert!(error.source().is_none());

    let phased = require_rejected_test_result(
        combine_package_exercise_and_cleanup_at_phase(
            Err("private-phased-detail".into()),
            Ok(()),
            Some("recovery.request-sent"),
        ),
        "phased exercise failure unexpectedly succeeded",
    )?;
    assert_eq!(
        phased.to_string(),
        "package exercise failed at fixed phase recovery.request-sent"
    );
    assert!(!format!("{phased:?}").contains("private-phased-detail"));

    let exercise_only: Result<(), Box<dyn Error>> = Err("private-exercise-detail".into());
    assert_eq!(
        require_rejected_test_result(
            combine_package_exercise_and_cleanup(exercise_only, Ok(())),
            "exercise failure unexpectedly succeeded",
        )?
        .to_string(),
        "package exercise failed"
    );
    let cleanup_only: Result<(), Box<dyn Error>> = Err("private-cleanup-detail".into());
    assert_eq!(
        require_rejected_test_result(
            combine_package_exercise_and_cleanup(Ok(()), cleanup_only),
            "cleanup failure unexpectedly succeeded",
        )?
        .to_string(),
        "package cleanup failed"
    );

    let cleanup_phased = require_rejected_test_result(
        combine_package_exercise_and_cleanup_at_phases(
            Ok(()),
            Err("private network authority and credential detail".into()),
            None,
            Some("package-network.config-contract"),
        ),
        "phased cleanup failure unexpectedly succeeded",
    )?;
    assert_eq!(
        cleanup_phased.to_string(),
        "package cleanup failed at fixed cleanup phase package-network.config-contract"
    );
    assert!(!format!("{cleanup_phased:?}").contains("private network"));
    assert!(cleanup_phased.source().is_none());

    let both_phased = require_rejected_test_result(
        combine_package_exercise_and_cleanup_at_phases(
            Err("private exercise detail".into()),
            Err("private cleanup detail".into()),
            Some("exercise.suspend-observed"),
            Some("package-network.authority"),
        ),
        "two phased failures unexpectedly succeeded",
    )?;
    assert_eq!(
        both_phased.to_string(),
        concat!(
            "package exercise failed; package cleanup failed",
            " at fixed phase exercise.suspend-observed",
            "; fixed cleanup phase package-network.authority"
        )
    );
    assert!(!format!("{both_phased:?}").contains("private"));

    let recovery_case_marker = package_recovery_case_failure_marker(
        PackageRecoveryTrigger::OwnerEof,
        RecoveryCheckpoint::Suspended,
    );
    let recovery_case = require_rejected_test_result(
        combine_package_exercise_and_cleanup_at_recovery_case(
            Err("private provider payload and path".into()),
            Ok(()),
            Some("recovery.drive-failed.exit-input-observation"),
            None,
            recovery_case_marker,
        ),
        "a failed recovery case unexpectedly succeeded",
    )?;
    assert_eq!(
        recovery_case.to_string(),
        concat!(
            "package exercise failed at fixed phase ",
            "recovery.drive-failed.exit-input-observation; fixed recovery case ",
            "recovery.case-failed.owner-eof.suspended-v1"
        )
    );
    let recovery_debug = format!("{recovery_case:?}");
    assert!(recovery_debug.contains(recovery_case_marker));
    assert!(!recovery_debug.contains("private"));
    assert!(recovery_case.source().is_none());

    let causal_recovery = require_rejected_test_result(
        combine_package_exercise_and_cleanup_with_evidence(
            Err("private retained-recovery detail".into()),
            Ok(()),
            PackageOperationFailureEvidence::new(
                Some(PackageRecoveryDriveFailure::InitialGate.marker()),
                Some(PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0]),
            ),
            None,
            None,
            None,
            None,
        ),
        "a causal retained-recovery failure unexpectedly succeeded",
    )?;
    assert_eq!(
        causal_recovery.to_string(),
        format!(
            "package exercise failed at fixed phase {}; fixed secondary failure {}",
            PackageRecoveryDriveFailure::InitialGate.marker(),
            PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0]
        )
    );
    assert!(!format!("{causal_recovery:?}").contains("private retained"));
    assert!(causal_recovery.source().is_none());

    let preserved = require_rejected_test_result(
        combine_package_exercise_and_cleanup_with_evidence(
            Err("private PTY bytes and credentials".into()),
            Ok(()),
            PackageOperationFailureEvidence::primary(Some(
                "startup-failure.compatibility.subtype.transport",
            )),
            None,
            None,
            Some(PackageHandoffProbePhase::ForkResponseValidated),
            Some(PathBuf::from("/tmp/cf-fixed-evidence")),
        ),
        "a failed handoff probe unexpectedly succeeded",
    )?;
    assert_eq!(
        preserved.to_string(),
        concat!(
            "package exercise failed at fixed phase ",
            "startup-failure.compatibility.subtype.transport; ",
            "last fixed handoff probe phase handoff.fork-response-validated; ",
            "package evidence root preserved at /tmp/cf-fixed-evidence"
        )
    );
    let preserved_debug = format!("{preserved:?}");
    assert!(preserved_debug.contains("ForkResponseValidated"));
    assert!(preserved_debug.contains("/tmp/cf-fixed-evidence"));
    assert!(!preserved_debug.contains("private PTY bytes"));
    assert!(!preserved_debug.contains("credentials"));
    assert!(preserved.source().is_none());
    Ok(())
}

#[test]
fn package_first_failure_phase_cannot_be_overwritten_by_cleanup_diagnostics() {
    assert_eq!(
        select_package_failure_phase(
            Some("exercise.tui-group-validation-failed.job-identity"),
            Some("initial-size-observed"),
            Some("session-terminal.tui.forced"),
        ),
        Some("exercise.tui-group-validation-failed.job-identity")
    );
    assert_eq!(
        select_package_failure_phase(
            None,
            Some("initial-size-observed"),
            Some("session-terminal.tui.forced"),
        ),
        Some("initial-size-observed")
    );
    assert_eq!(select_package_failure_phase(None, None, None), None);
}

#[test]
fn package_failure_phase_prefers_a_late_finalized_startup_failure_but_not_cleanup_failure() {
    assert_eq!(
        select_package_failure_phase(
            None,
            Some("initial-size-observed"),
            Some("startup-failure.monitor-connect"),
        ),
        Some("startup-failure.monitor-connect")
    );
    assert_eq!(
        select_package_failure_phase(
            None,
            Some("initial-size-observed"),
            Some(PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0]),
        ),
        Some("initial-size-observed")
    );
    assert_eq!(
        select_package_failure_phase(
            Some("exercise.tui-group-validation-failed.job-identity"),
            Some("initial-size-observed"),
            Some(PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0]),
        ),
        Some("exercise.tui-group-validation-failed.job-identity")
    );
    assert_eq!(
        select_package_failure_phase(
            None,
            Some("exercise.initial-input-observed"),
            Some("package-backend.response.prompt-missing"),
        ),
        Some("package-backend.response.prompt-missing")
    );
}

#[test]
fn official_tui_pre_generation_cleanup_joins_backend_and_deletes_owned_scratch_without_inference_claim()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let root = scratch.root.clone();
    let backend = PackageSessionBackend::spawn()?;
    let (_placeholder_sender, output_result) = mpsc::sync_channel(1);
    let mut harness = OfficialTuiPackageHarness {
        _provider_suite_budget: PackageProviderSuiteBudget::Official,
        scratch: Some(scratch),
        backend: Some(backend),
        coordinator: None,
        completion: None,
        provider_target: PackageProviderTarget::Official,
        startup_fault: None,
        inference_expectation: PackageInferenceExpectation::ExactlyOne,
        recovery_checkpoint: None,
        recovery_request_state: PackageRecoveryRequestState::Available,
        generation_cleanup: None,
        generation_deadline_fence: None,
        guardian_startup_arm_observed: false,
        master: None,
        initial_termios: None,
        output_cancel: None,
        output_result,
        startup_sentinel_observed: None,
        response_sentinel_observed: None,
        output_worker: None,
        output_finished: true,
        last_handoff_probe_phase: None,
        recovery_failure_evidence: PackageRecoveryFailureEvidence::default(),
        last_fixed_failure_detail: None,
        last_fixed_cleanup_failure_detail: None,
    };
    let report = root.join("supervisor-report");
    private_directory(&report)?;
    write_private_new(
        &report.join("session-terminal.operation.component-tui"),
        b"classified\n",
    )?;

    let cleanup = harness.cleanup();
    assert!(
        cleanup.is_ok(),
        "pre-generation cleanup must not claim inference evidence: {cleanup:?}"
    );
    assert!(
        !root.exists(),
        "pre-generation cleanup retained its owned setup scratch"
    );
    assert_eq!(
        harness.latest_fixed_failure_detail(),
        Some("session-terminal.operation.component-tui"),
        "cleanup must cache the fixed terminal diagnostic before deleting scratch"
    );
    Ok(())
}

#[test]
fn official_tui_pre_generation_cleanup_aggregates_infrastructure_failures_before_deleting_scratch()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let root = scratch.root.clone();
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    drop(listener);
    let (backend_cancel, _backend_cancellation) = mpsc::sync_channel(1);
    let (_inference_completion, inference_completed) = mpsc::sync_channel(1);
    let backend_worker =
        thread::spawn(|| Err("injected package session backend transport failure".to_owned()));
    let backend = PackageSessionBackend {
        address,
        deadline: Instant::now() + IO_TIMEOUT,
        cancel: Some(backend_cancel),
        inference_completed,
        worker: Some(backend_worker),
    };
    let (output_cancel, _output_cancellation) = mpsc::sync_channel(1);
    let (output_sender, output_result) = mpsc::sync_channel(1);
    output_sender.send(Err("injected package PTY output failure".to_owned()))?;
    let output_worker = thread::spawn(|| {});
    let mut harness = OfficialTuiPackageHarness {
        _provider_suite_budget: PackageProviderSuiteBudget::Official,
        scratch: Some(scratch),
        backend: Some(backend),
        coordinator: None,
        completion: None,
        provider_target: PackageProviderTarget::Official,
        startup_fault: None,
        inference_expectation: PackageInferenceExpectation::ExactlyOne,
        recovery_checkpoint: None,
        recovery_request_state: PackageRecoveryRequestState::Available,
        generation_cleanup: None,
        generation_deadline_fence: None,
        guardian_startup_arm_observed: false,
        master: None,
        initial_termios: None,
        output_cancel: Some(output_cancel),
        output_result,
        startup_sentinel_observed: None,
        response_sentinel_observed: None,
        output_worker: Some(output_worker),
        output_finished: false,
        last_handoff_probe_phase: None,
        recovery_failure_evidence: PackageRecoveryFailureEvidence::default(),
        last_fixed_failure_detail: None,
        last_fixed_cleanup_failure_detail: None,
    };

    let error = match harness.cleanup() {
        Ok(()) => return Err("injected cleanup infrastructure failures were ignored".into()),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("package PTY output"), "{error}");
    assert!(error.contains("package session backend"), "{error}");
    assert!(
        !root.exists(),
        "later owned scratch cleanup was skipped after an earlier failure"
    );
    Ok(())
}

type OfficialNetworkCleanupHarnessFixture = (
    OfficialTuiPackageHarness,
    PathBuf,
    std::net::SocketAddr,
    Arc<AtomicBool>,
);

fn started_official_harness_for_network_cleanup_test()
-> Result<OfficialNetworkCleanupHarnessFixture, Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let root = scratch.root.clone();
    private_directory(&root.join("supervisor-report"))?;
    let backend = PackageSessionBackend::spawn()?;
    let backend_address = backend.address();
    let mut coordinator = Command::new("/usr/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if !coordinator.wait()?.success() {
        return Err("network cleanup test coordinator fixture failed".into());
    }

    let (output_cancel, output_cancellation) = mpsc::sync_channel(1);
    let (output_sender, output_result) = mpsc::sync_channel(1);
    let output_joined = Arc::new(AtomicBool::new(false));
    let output_joined_worker = Arc::clone(&output_joined);
    let output_worker = thread::spawn(move || {
        if output_cancellation.recv_timeout(IO_TIMEOUT).is_ok() {
            output_joined_worker.store(true, Ordering::SeqCst);
            let _ = output_sender.send(Ok(PackageOutputDrain {
                total_bytes: 0,
                response_sentinel_seen: false,
                eof: true,
                handoff_probe_phase: None,
            }));
        }
    });
    let harness = OfficialTuiPackageHarness {
        _provider_suite_budget: PackageProviderSuiteBudget::Official,
        scratch: Some(scratch),
        backend: Some(backend),
        coordinator: Some(coordinator),
        completion: None,
        provider_target: PackageProviderTarget::Official,
        startup_fault: None,
        inference_expectation: PackageInferenceExpectation::Zero,
        recovery_checkpoint: None,
        recovery_request_state: PackageRecoveryRequestState::Available,
        generation_cleanup: Some(PackageGenerationCleanupEvidence {
            exact_coordinator_wait: true,
            completion_verified: true,
            reported_groups_absent: true,
            runtime_empty: true,
        }),
        generation_deadline_fence: Some(PackageGenerationDeadlineFence::starting_at(
            Instant::now(),
        )?),
        guardian_startup_arm_observed: false,
        master: None,
        initial_termios: None,
        output_cancel: Some(output_cancel),
        output_result,
        startup_sentinel_observed: None,
        response_sentinel_observed: None,
        output_worker: Some(output_worker),
        output_finished: false,
        last_handoff_probe_phase: None,
        recovery_failure_evidence: PackageRecoveryFailureEvidence::default(),
        last_fixed_failure_detail: None,
        last_fixed_cleanup_failure_detail: None,
    };
    Ok((harness, root, backend_address, output_joined))
}

#[test]
fn official_network_cleanup_runs_after_workers_close_and_before_scratch_deletion()
-> Result<(), Box<dyn Error>> {
    let (mut harness, root, backend_address, output_joined) =
        started_official_harness_for_network_cleanup_test()?;
    let mut verifier_calls = 0_u8;
    harness.cleanup_with_network_verifier(|observed_root, observed_backend| {
        verifier_calls = verifier_calls.saturating_add(1);
        if observed_root != root || observed_backend != backend_address {
            return Err(PackageNetworkHermeticityFailure::ConfigContract);
        }
        if !observed_root.exists() {
            return Err(PackageNetworkHermeticityFailure::ConfigContract);
        }
        if !output_joined.load(Ordering::SeqCst) {
            return Err(PackageNetworkHermeticityFailure::ConfigContract);
        }
        let error = match TcpStream::connect(observed_backend) {
            Err(error) => error,
            Ok(stream) => {
                drop(stream);
                return Err(PackageNetworkHermeticityFailure::ConfigContract);
            }
        };
        if error.kind() != io::ErrorKind::ConnectionRefused {
            return Err(PackageNetworkHermeticityFailure::ConfigContract);
        }
        Ok(())
    })?;
    assert_eq!(verifier_calls, 1);
    assert!(
        !root.exists(),
        "network proof did not precede scratch deletion"
    );
    assert_eq!(harness.latest_fixed_cleanup_failure_detail(), None);
    Ok(())
}

#[test]
fn official_network_cleanup_failure_preserves_owned_evidence_after_closing_workers()
-> Result<(), Box<dyn Error>> {
    let (mut harness, root, _backend_address, _output_joined) =
        started_official_harness_for_network_cleanup_test()?;
    let outcome = harness.cleanup_after_exercise_with_network_verifier(false, |_, _| {
        Err(PackageNetworkHermeticityFailure::ConfigContract)
    });
    let error = require_rejected_test_result(
        outcome.result,
        "an injected network verification failure was accepted",
    )?;
    let evidence = match outcome.scratch {
        PackageScratchDisposition::Preserved(evidence) => evidence,
        PackageScratchDisposition::Deleted => {
            return Err("network cleanup failure deleted its diagnostic evidence".into());
        }
        PackageScratchDisposition::Unavailable => {
            return Err("network cleanup failure lost its diagnostic evidence authority".into());
        }
    };
    assert_eq!(evidence.root(), root);
    assert!(root.exists());
    assert!(!error.to_string().contains("credential"));
    assert!(!format!("{error:?}").contains("credential"));
    assert_eq!(
        harness.latest_fixed_cleanup_failure_detail(),
        Some("package-network.config-contract")
    );
    evidence.cleanup()
}

#[test]
fn dropping_a_started_official_harness_closes_workers_and_preserves_owned_evidence()
-> Result<(), Box<dyn Error>> {
    let (harness, root, backend_address, output_joined) =
        started_official_harness_for_network_cleanup_test()?;
    drop(harness);

    assert!(
        output_joined.load(Ordering::SeqCst),
        "unexpected Drop did not join the package PTY output worker"
    );
    let backend_error = match TcpStream::connect(backend_address) {
        Err(error) => error,
        Ok(stream) => {
            drop(stream);
            return Err("unexpected Drop left the package backend listening".into());
        }
    };
    assert_eq!(backend_error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(
        root.exists(),
        "unexpected Drop deleted started-generation diagnostic evidence"
    );

    let metadata = fs::symlink_metadata(&root)?;
    PreservedPackageEvidence::new(PackageScratch {
        identity: (metadata.dev(), metadata.ino()),
        codex_home: root.join("codex-home"),
        workspace: root.join("workspace"),
        environment_home: root.join("environment"),
        compatibility_stage_parent: root.join("s"),
        root,
    })?
    .cleanup()
}

#[test]
fn started_package_setup_failure_closes_workers_and_preserves_owned_evidence()
-> Result<(), Box<dyn Error>> {
    let (harness, root, backend_address, output_joined) =
        started_official_harness_for_network_cleanup_test()?;
    let error = require_rejected_test_result(
        harness.finish_setup_with_network_verifier(
            Err("private initial PTY write and credential detail".into()),
            PackageHarnessSetupPhase::InitialPtyWrite,
            |observed_root, observed_backend| {
                if observed_root != root || observed_backend != backend_address {
                    return Err(PackageNetworkHermeticityFailure::ConfigContract);
                }
                if !output_joined.load(Ordering::SeqCst) {
                    return Err(PackageNetworkHermeticityFailure::ConfigContract);
                }
                Ok(())
            },
        ),
        "a started package setup failure unexpectedly succeeded",
    )?;

    assert!(
        output_joined.load(Ordering::SeqCst),
        "started setup failure did not join the package PTY output worker"
    );
    let backend_error = match TcpStream::connect(backend_address) {
        Err(error) => error,
        Ok(stream) => {
            drop(stream);
            return Err("started setup failure left the package backend listening".into());
        }
    };
    assert_eq!(backend_error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(
        root.exists(),
        "started setup failure deleted its diagnostic evidence"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "package harness setup failed at fixed phase package-setup.initial-pty-write \
             after generation start; \
             package evidence root preserved at {}",
            root.display()
        )
    );
    let debug = format!("{error:?}");
    assert!(!debug.contains("private initial PTY write"));
    assert!(!debug.contains("credential"));
    assert!(error.source().is_none());

    let metadata = fs::symlink_metadata(&root)?;
    PreservedPackageEvidence::new(PackageScratch {
        identity: (metadata.dev(), metadata.ino()),
        codex_home: root.join("codex-home"),
        workspace: root.join("workspace"),
        environment_home: root.join("environment"),
        compatibility_stage_parent: root.join("s"),
        root,
    })?
    .cleanup()
}

#[test]
fn official_failed_exercise_cleanup_closes_workers_and_preserves_owned_evidence()
-> Result<(), Box<dyn Error>> {
    let (mut harness, root, backend_address, output_joined) =
        started_official_harness_for_network_cleanup_test()?;
    let outcome = harness.cleanup_after_exercise_with_network_verifier(
        true,
        |observed_root, observed_backend| {
            if observed_root != root || observed_backend != backend_address {
                return Err(PackageNetworkHermeticityFailure::ConfigContract);
            }
            if !output_joined.load(Ordering::SeqCst) {
                return Err(PackageNetworkHermeticityFailure::ConfigContract);
            }
            let error = match TcpStream::connect(observed_backend) {
                Err(error) => error,
                Ok(stream) => {
                    drop(stream);
                    return Err(PackageNetworkHermeticityFailure::ConfigContract);
                }
            };
            if error.kind() != io::ErrorKind::ConnectionRefused {
                return Err(PackageNetworkHermeticityFailure::ConfigContract);
            }
            Ok(())
        },
    );
    outcome.result?;
    let evidence = match outcome.scratch {
        PackageScratchDisposition::Preserved(evidence) => evidence,
        PackageScratchDisposition::Deleted => {
            return Err("failed exercise deleted its diagnostic evidence".into());
        }
        PackageScratchDisposition::Unavailable => {
            return Err("failed exercise lost its diagnostic evidence authority".into());
        }
    };
    assert_eq!(evidence.root(), root);
    assert!(root.exists());
    evidence.cleanup()
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PackageGenerationCleanupEvidence {
    exact_coordinator_wait: bool,
    completion_verified: bool,
    reported_groups_absent: bool,
    runtime_empty: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageScratchCleanupDecision {
    Delete,
    Retain,
}

impl PackageGenerationCleanupEvidence {
    const fn scratch_decision(self) -> PackageScratchCleanupDecision {
        if self.exact_coordinator_wait
            && self.completion_verified
            && self.reported_groups_absent
            && self.runtime_empty
        {
            PackageScratchCleanupDecision::Delete
        } else {
            PackageScratchCleanupDecision::Retain
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageCompletionObservation {
    Pending,
    Verified,
    RetainedUnrecoverable,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageRecoveryRequestObservation {
    Sent,
    AttemptConsumedBoundaryUnknown,
    AlreadyConsumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageRecoveryTrigger {
    GenerationBoundRequest,
    OwnerEof,
}

const fn package_recovery_case_failure_marker(
    trigger: PackageRecoveryTrigger,
    checkpoint: RecoveryCheckpoint,
) -> &'static str {
    match (trigger, checkpoint) {
        (PackageRecoveryTrigger::GenerationBoundRequest, RecoveryCheckpoint::StartupQueued) => {
            "recovery.case-failed.request.startup-queued-v1"
        }
        (PackageRecoveryTrigger::GenerationBoundRequest, RecoveryCheckpoint::Ready) => {
            "recovery.case-failed.request.ready-v1"
        }
        (PackageRecoveryTrigger::GenerationBoundRequest, RecoveryCheckpoint::Active) => {
            "recovery.case-failed.request.active-v1"
        }
        (PackageRecoveryTrigger::GenerationBoundRequest, RecoveryCheckpoint::Suspended) => {
            "recovery.case-failed.request.suspended-v1"
        }
        (PackageRecoveryTrigger::GenerationBoundRequest, RecoveryCheckpoint::RetainedQuiescing) => {
            "recovery.case-failed.request.retained-quiescing-v1"
        }
        (
            PackageRecoveryTrigger::GenerationBoundRequest,
            RecoveryCheckpoint::RetainedRestorePending,
        ) => "recovery.case-failed.request.retained-restore-pending-v1",
        (
            PackageRecoveryTrigger::GenerationBoundRequest,
            RecoveryCheckpoint::RetainedCleanupPending,
        ) => "recovery.case-failed.request.retained-cleanup-pending-v1",
        (PackageRecoveryTrigger::OwnerEof, RecoveryCheckpoint::StartupQueued) => {
            "recovery.case-failed.owner-eof.startup-queued-v1"
        }
        (PackageRecoveryTrigger::OwnerEof, RecoveryCheckpoint::Ready) => {
            "recovery.case-failed.owner-eof.ready-v1"
        }
        (PackageRecoveryTrigger::OwnerEof, RecoveryCheckpoint::Active) => {
            "recovery.case-failed.owner-eof.active-v1"
        }
        (PackageRecoveryTrigger::OwnerEof, RecoveryCheckpoint::Suspended) => {
            "recovery.case-failed.owner-eof.suspended-v1"
        }
        (PackageRecoveryTrigger::OwnerEof, RecoveryCheckpoint::RetainedQuiescing) => {
            "recovery.case-failed.owner-eof.retained-quiescing-v1"
        }
        (PackageRecoveryTrigger::OwnerEof, RecoveryCheckpoint::RetainedRestorePending) => {
            "recovery.case-failed.owner-eof.retained-restore-pending-v1"
        }
        (PackageRecoveryTrigger::OwnerEof, RecoveryCheckpoint::RetainedCleanupPending) => {
            "recovery.case-failed.owner-eof.retained-cleanup-pending-v1"
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageExactCoordinatorStateObservation {
    Reaped,
    Stopped,
    NotProvenStopped,
}

fn classify_exact_coordinator_snapshot(
    pid: i32,
    current_user: u32,
    members: &[PackageProcessState],
) -> PackageExactCoordinatorStateObservation {
    let mut exact = members.iter().filter(|member| member.pid == pid);
    let stopped = exact.next().is_some_and(|member| {
        member.process_group == pid && member.user == current_user && member.state == b'T'
    }) && exact.next().is_none();
    if stopped {
        PackageExactCoordinatorStateObservation::Stopped
    } else {
        PackageExactCoordinatorStateObservation::NotProvenStopped
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageHealthyLifecycleObservation {
    completion_ready: bool,
    coordinator_reaped: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageCleanupFailure {
    Deadline,
    CompletionBoundary,
    RecoveryBoundary,
    HealthyLifecycle,
    ExactCoordinatorFallback,
    CompletionProof,
    ReportedGroupsProof,
    RuntimeProof,
    RetainedUnrecoverable,
}

impl fmt::Display for PackageCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package generation cleanup proof failed")
    }
}

impl Error for PackageCleanupFailure {}

#[derive(Clone, Copy, Debug)]
struct PackageCleanupDeadlines {
    normal_completion: Instant,
    recovery_request: Instant,
    healthy_lifecycle: Instant,
    coordinator_term: Instant,
    coordinator_kill: Instant,
    completion_proof: Instant,
    reported_groups_proof: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageCleanupBudget {
    startup: Duration,
    startup_handoff_margin: Duration,
    external: Duration,
    normal_completion: Duration,
    recovery_request: Duration,
    healthy_lifecycle: Duration,
    coordinator_term: Duration,
    coordinator_kill: Duration,
    completion_proof: Duration,
    reported_groups_proof: Duration,
    external_observation_margin: Duration,
}

struct PackageDeterministicSuiteBudget {
    capacity: Duration,
    available: Duration,
}

impl PackageDeterministicSuiteBudget {
    const fn new(capacity: Duration) -> Self {
        Self {
            capacity,
            available: capacity,
        }
    }

    const fn available(&self) -> Duration {
        self.available
    }

    fn try_reserve(&mut self, required: Duration) -> Option<PackageDeterministicSuiteReservation> {
        if required.is_zero() {
            return None;
        }
        self.available = self.available.checked_sub(required)?;
        Some(PackageDeterministicSuiteReservation { reserved: required })
    }

    fn settle(&mut self, reservation: PackageDeterministicSuiteReservation, elapsed: Duration) {
        if let Some(unused) = reservation.reserved.checked_sub(elapsed) {
            if let Some(refunded) = self
                .available
                .checked_add(unused)
                .filter(|refunded| *refunded <= self.capacity)
            {
                self.available = refunded;
            }
        } else if let Some(overrun) = elapsed.checked_sub(reservation.reserved) {
            self.available = self.available.saturating_sub(overrun);
        }
    }
}

struct PackageDeterministicSuiteReservation {
    reserved: Duration,
}

struct PackageDeterministicSuiteLease {
    started: Instant,
    reservation: Option<PackageDeterministicSuiteReservation>,
}

enum PackageProviderSuiteBudget {
    Official,
    Deterministic {
        _lease: PackageDeterministicSuiteLease,
    },
}

impl PackageProviderSuiteBudget {
    const fn provider_target(&self) -> PackageProviderTarget {
        match self {
            Self::Official => PackageProviderTarget::Official,
            Self::Deterministic { .. } => PackageProviderTarget::DeterministicFixture,
        }
    }
}

impl Drop for PackageDeterministicSuiteLease {
    fn drop(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let elapsed = self.started.elapsed();
        if let Ok(mut budget) = package_deterministic_suite_budget().lock() {
            budget.settle(reservation, elapsed);
        }
    }
}

fn package_deterministic_suite_budget() -> &'static Mutex<PackageDeterministicSuiteBudget> {
    static BUDGET: OnceLock<Mutex<PackageDeterministicSuiteBudget>> = OnceLock::new();
    BUDGET.get_or_init(|| {
        Mutex::new(PackageDeterministicSuiteBudget::new(
            PACKAGE_DETERMINISTIC_SUITE_TIMEOUT,
        ))
    })
}

fn reserve_package_deterministic_generation()
-> Result<PackageDeterministicSuiteLease, Box<dyn Error>> {
    let reservation = package_deterministic_suite_budget()
        .lock()
        .map_err(|_| "package-deterministic-suite-budget-unavailable-v1")?
        .try_reserve(PACKAGE_DETERMINISTIC_EXTERNAL_HARD_TIMEOUT)
        .ok_or("package-deterministic-suite-budget-exhausted-v1")?;
    Ok(PackageDeterministicSuiteLease {
        started: Instant::now(),
        reservation: Some(reservation),
    })
}

impl PackageCleanupBudget {
    const fn for_target(target: PackageProviderTarget) -> Self {
        match target {
            PackageProviderTarget::Official => Self {
                startup: PACKAGE_SUPERVISOR_STARTUP_TIMEOUT,
                startup_handoff_margin: PACKAGE_PARENT_STARTUP_HANDOFF_MARGIN,
                external: PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT,
                normal_completion: PACKAGE_CLEANUP_NORMAL_COMPLETION_RACE,
                recovery_request: PACKAGE_CLEANUP_RECOVERY_REQUEST_TIMEOUT,
                healthy_lifecycle: PACKAGE_CLEANUP_HEALTHY_LIFECYCLE_GRACE,
                coordinator_term: PACKAGE_CLEANUP_COORDINATOR_TERM_GRACE,
                coordinator_kill: PACKAGE_CLEANUP_COORDINATOR_KILL_WAIT,
                completion_proof: PACKAGE_CLEANUP_COMPLETION_PROOF_TIMEOUT,
                reported_groups_proof: PACKAGE_CLEANUP_GROUP_PROOF_TIMEOUT,
                external_observation_margin: PACKAGE_CLEANUP_EXTERNAL_OBSERVATION_MARGIN,
            },
            PackageProviderTarget::DeterministicFixture => Self {
                startup: PACKAGE_DETERMINISTIC_SUPERVISOR_TIMEOUT,
                startup_handoff_margin: Duration::ZERO,
                external: PACKAGE_DETERMINISTIC_EXTERNAL_HARD_TIMEOUT,
                normal_completion: PACKAGE_CLEANUP_NORMAL_COMPLETION_RACE,
                recovery_request: PACKAGE_CLEANUP_RECOVERY_REQUEST_TIMEOUT,
                healthy_lifecycle: PACKAGE_DETERMINISTIC_CLEANUP_HEALTHY_LIFECYCLE_GRACE,
                coordinator_term: PACKAGE_DETERMINISTIC_CLEANUP_COORDINATOR_TERM_GRACE,
                coordinator_kill: PACKAGE_DETERMINISTIC_CLEANUP_COORDINATOR_KILL_WAIT,
                completion_proof: PACKAGE_DETERMINISTIC_CLEANUP_COMPLETION_PROOF_TIMEOUT,
                reported_groups_proof: PACKAGE_DETERMINISTIC_CLEANUP_GROUP_PROOF_TIMEOUT,
                external_observation_margin:
                    PACKAGE_DETERMINISTIC_CLEANUP_EXTERNAL_OBSERVATION_MARGIN,
            },
        }
    }

    fn cleanup_reserve(self) -> Result<Duration, PackageCleanupFailure> {
        [
            self.normal_completion,
            self.recovery_request,
            self.healthy_lifecycle,
            self.coordinator_term,
            self.coordinator_kill,
            self.completion_proof,
            self.reported_groups_proof,
        ]
        .into_iter()
        .try_fold(Duration::ZERO, |total, duration| {
            total.checked_add(duration)
        })
        .ok_or(PackageCleanupFailure::Deadline)
    }

    fn startup_through_handoff(self) -> Result<Duration, PackageCleanupFailure> {
        self.startup
            .checked_add(self.startup_handoff_margin)
            .ok_or(PackageCleanupFailure::Deadline)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageGenerationDeadlineFence {
    origin: Instant,
    recovery_start: Instant,
    external_fence: Instant,
    cleanup_fence: Instant,
    cleanup_budget: PackageCleanupBudget,
}

impl PackageGenerationDeadlineFence {
    fn starting_at(origin: Instant) -> Result<Self, PackageCleanupFailure> {
        Self::starting_at_with_budget(
            origin,
            PackageCleanupBudget::for_target(PackageProviderTarget::Official),
        )
    }

    fn starting_at_for_target(
        origin: Instant,
        target: PackageProviderTarget,
    ) -> Result<Self, PackageCleanupFailure> {
        Self::starting_at_with_budget(origin, PackageCleanupBudget::for_target(target))
    }

    fn starting_at_with_timeout(
        origin: Instant,
        external_timeout: Duration,
    ) -> Result<Self, PackageCleanupFailure> {
        let mut budget = PackageCleanupBudget::for_target(PackageProviderTarget::Official);
        budget.external = external_timeout;
        Self::starting_at_with_budget(origin, budget)
    }

    fn starting_at_with_budget(
        origin: Instant,
        budget: PackageCleanupBudget,
    ) -> Result<Self, PackageCleanupFailure> {
        let recovery_start_offset = budget.startup_through_handoff()?;
        let recovery_start = origin
            .checked_add(recovery_start_offset)
            .ok_or(PackageCleanupFailure::Deadline)?;
        let external_fence = origin
            .checked_add(budget.external)
            .ok_or(PackageCleanupFailure::Deadline)?;
        let cleanup_fence = external_fence
            .checked_sub(budget.external_observation_margin)
            .filter(|cleanup_fence| *cleanup_fence > recovery_start)
            .ok_or(PackageCleanupFailure::Deadline)?;
        let cleanup_reserve = budget.cleanup_reserve()?;
        if recovery_start
            .checked_add(cleanup_reserve)
            .filter(|cleanup_end| *cleanup_end <= cleanup_fence)
            .is_none()
        {
            return Err(PackageCleanupFailure::Deadline);
        }
        Ok(Self {
            origin,
            recovery_start,
            external_fence,
            cleanup_fence,
            cleanup_budget: budget,
        })
    }

    fn guardian_startup_arm_observation_deadline(self) -> Result<Instant, PackageCleanupFailure> {
        let post_arm_reserve = self
            .cleanup_budget
            .startup_through_handoff()?
            .checked_add(self.cleanup_budget.cleanup_reserve()?)
            .ok_or(PackageCleanupFailure::Deadline)?;
        self.cleanup_fence
            .checked_sub(post_arm_reserve)
            .filter(|deadline| *deadline >= self.origin)
            .ok_or(PackageCleanupFailure::Deadline)
    }

    /// Re-anchors the package parent's recovery boundary to a local
    /// observation made only after the Guardian minted its complete startup
    /// deadline. Because the observation is no earlier than the child arm,
    /// adding the same startup interval plus the explicit handoff/report
    /// margin proves the parent cannot recover first.
    fn after_guardian_startup_armed(
        mut self,
        observed_at: Instant,
    ) -> Result<Self, PackageCleanupFailure> {
        if observed_at < self.origin
            || observed_at > self.guardian_startup_arm_observation_deadline()?
        {
            return Err(PackageCleanupFailure::Deadline);
        }
        let recovery_start = observed_at
            .checked_add(self.cleanup_budget.startup_through_handoff()?)
            .ok_or(PackageCleanupFailure::Deadline)?;
        if recovery_start
            .checked_add(self.cleanup_budget.cleanup_reserve()?)
            .filter(|cleanup_end| *cleanup_end <= self.cleanup_fence)
            .is_none()
        {
            return Err(PackageCleanupFailure::Deadline);
        }
        self.recovery_start = recovery_start;
        Ok(self)
    }

    fn recovery_checkpoint_deadline(self, now: Instant) -> Result<Instant, PackageCleanupFailure> {
        if now < self.origin || now >= self.recovery_start {
            return Err(PackageCleanupFailure::Deadline);
        }
        Ok(self.recovery_start)
    }

    fn exercise_deadline(
        self,
        now: Instant,
        requested_timeout: Duration,
    ) -> Result<Instant, PackageCleanupFailure> {
        if now < self.origin || now >= self.recovery_start {
            return Err(PackageCleanupFailure::Deadline);
        }
        now.checked_add(requested_timeout)
            .map(|requested_deadline| requested_deadline.min(self.recovery_start))
            .ok_or(PackageCleanupFailure::Deadline)
    }
}

impl PackageCleanupDeadlines {
    fn within_generation(
        fence: PackageGenerationDeadlineFence,
        cleanup_start: Instant,
    ) -> Result<Self, PackageCleanupFailure> {
        if cleanup_start < fence.origin || cleanup_start >= fence.cleanup_fence {
            return Err(PackageCleanupFailure::Deadline);
        }
        let capped_add = |start: Instant, duration: Duration| {
            start
                .checked_add(duration)
                .map(|candidate| candidate.min(fence.cleanup_fence))
                .ok_or(PackageCleanupFailure::Deadline)
        };
        let budget = fence.cleanup_budget;
        let normal_completion = capped_add(cleanup_start, budget.normal_completion)?;
        let recovery_request = capped_add(normal_completion, budget.recovery_request)?;
        let healthy_lifecycle = capped_add(recovery_request, budget.healthy_lifecycle)?;
        let coordinator_term = capped_add(healthy_lifecycle, budget.coordinator_term)?;
        let coordinator_kill = capped_add(coordinator_term, budget.coordinator_kill)?;
        let completion_proof = capped_add(coordinator_kill, budget.completion_proof)?;
        let reported_groups_proof = capped_add(completion_proof, budget.reported_groups_proof)?;
        Ok(Self {
            normal_completion,
            recovery_request,
            healthy_lifecycle,
            coordinator_term,
            coordinator_kill,
            completion_proof,
            reported_groups_proof,
        })
    }
}

trait PackageGenerationCleanupOperations {
    fn poll_normal_completion(
        &mut self,
        deadline: Instant,
    ) -> Result<PackageCompletionObservation, PackageCleanupFailure>;

    fn request_recovery_once(
        &mut self,
        deadline: Instant,
    ) -> Result<PackageRecoveryRequestObservation, PackageCleanupFailure>;

    fn observe_exact_coordinator_state(
        &mut self,
    ) -> Result<PackageExactCoordinatorStateObservation, PackageCleanupFailure>;

    fn wake_exact_coordinator(&mut self) -> Result<(), PackageCleanupFailure>;

    fn observe_healthy_lifecycle(
        &mut self,
        completion_ready: bool,
        coordinator_reaped: bool,
        deadline: Instant,
    ) -> Result<PackageHealthyLifecycleObservation, PackageCleanupFailure>;

    fn force_reap_exact_coordinator(
        &mut self,
        term_deadline: Instant,
        kill_deadline: Instant,
    ) -> Result<(), PackageCleanupFailure>;

    fn prove_completion(&mut self, deadline: Instant) -> Result<(), PackageCleanupFailure>;

    fn prove_reported_groups_absent(
        &mut self,
        deadline: Instant,
    ) -> Result<(), PackageCleanupFailure>;

    fn prove_runtime_empty(&mut self) -> Result<(), PackageCleanupFailure>;
}

fn drive_package_generation_cleanup<Operations: PackageGenerationCleanupOperations>(
    operations: &mut Operations,
    mut evidence: PackageGenerationCleanupEvidence,
    deadlines: PackageCleanupDeadlines,
) -> Result<PackageGenerationCleanupEvidence, PackageCleanupFailure> {
    if !evidence.exact_coordinator_wait || !evidence.completion_verified {
        let normal_completion = if evidence.completion_verified {
            PackageCompletionObservation::Verified
        } else {
            operations.poll_normal_completion(deadlines.normal_completion)?
        };
        match normal_completion {
            PackageCompletionObservation::RetainedUnrecoverable => {
                return Err(PackageCleanupFailure::RetainedUnrecoverable);
            }
            PackageCompletionObservation::Rejected => {
                return Err(PackageCleanupFailure::CompletionBoundary);
            }
            PackageCompletionObservation::Pending if !evidence.completion_verified => {
                // This is an explicit owner-initiated abort after setup or
                // exercise has already failed, not the retained-timeout
                // transition. The Guardian-arm acknowledgement reanchors the
                // selected recovery deadline; it must not make deterministic
                // teardown wait through a still-live startup window.
                match operations.request_recovery_once(deadlines.recovery_request)? {
                    PackageRecoveryRequestObservation::Sent
                    | PackageRecoveryRequestObservation::AttemptConsumedBoundaryUnknown
                    | PackageRecoveryRequestObservation::AlreadyConsumed => {}
                }
            }
            PackageCompletionObservation::Pending | PackageCompletionObservation::Verified => {}
        }

        if !evidence.exact_coordinator_wait {
            match operations.observe_exact_coordinator_state()? {
                PackageExactCoordinatorStateObservation::Reaped => {
                    evidence.exact_coordinator_wait = true;
                }
                PackageExactCoordinatorStateObservation::Stopped => {
                    operations.wake_exact_coordinator()?;
                }
                PackageExactCoordinatorStateObservation::NotProvenStopped => {}
            }
        }

        let completion_ready = evidence.completion_verified
            || normal_completion == PackageCompletionObservation::Verified;
        let observation = operations.observe_healthy_lifecycle(
            completion_ready,
            evidence.exact_coordinator_wait,
            deadlines.healthy_lifecycle,
        )?;
        if completion_ready && !observation.completion_ready {
            return Err(PackageCleanupFailure::HealthyLifecycle);
        }
        evidence.exact_coordinator_wait |= observation.coordinator_reaped;

        if !evidence.exact_coordinator_wait {
            operations.force_reap_exact_coordinator(
                deadlines.coordinator_term,
                deadlines.coordinator_kill,
            )?;
            evidence.exact_coordinator_wait = true;
        }
        if !evidence.completion_verified {
            operations.prove_completion(deadlines.completion_proof)?;
            evidence.completion_verified = true;
        }
    }

    if !evidence.reported_groups_absent {
        operations.prove_reported_groups_absent(deadlines.reported_groups_proof)?;
        evidence.reported_groups_absent = true;
    }
    if !evidence.runtime_empty {
        operations.prove_runtime_empty()?;
        evidence.runtime_empty = true;
    }
    Ok(evidence)
}

#[derive(Clone, Copy)]
struct PackageOutputDrain {
    total_bytes: usize,
    response_sentinel_seen: bool,
    eof: bool,
    handoff_probe_phase: Option<PackageHandoffProbePhase>,
}

impl OfficialTuiPackageHarness {
    fn spawn(
        executable: PathBuf,
        scratch: PackageScratch,
        backend: PackageSessionBackend,
    ) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_recovery_checkpoint(executable, scratch, backend, None)
    }

    fn spawn_with_recovery_checkpoint(
        executable: PathBuf,
        scratch: PackageScratch,
        backend: PackageSessionBackend,
        recovery_checkpoint: Option<RecoveryCheckpoint>,
    ) -> Result<Self, Box<dyn Error>> {
        Self::spawn_configured(
            executable,
            scratch,
            backend,
            recovery_checkpoint,
            PackageProviderSuiteBudget::Official,
            PackageInferenceExpectation::ExactlyOne,
            PackageStartupTestSeams::default(),
        )
    }

    fn spawn_deterministic_recovery(
        scratch: PackageScratch,
        backend: PackageSessionBackend,
        recovery_checkpoint: RecoveryCheckpoint,
        suite_budget: PackageDeterministicSuiteLease,
    ) -> Result<Self, Box<dyn Error>> {
        let executable = install_packaged_codex_provider_fixture(&scratch)?;
        let launcher = install_packaged_tui_launcher_fixture(&scratch)?;
        Self::spawn_configured(
            executable,
            scratch,
            backend,
            Some(recovery_checkpoint),
            PackageProviderSuiteBudget::Deterministic {
                _lease: suite_budget,
            },
            PackageInferenceExpectation::for_fixture_checkpoint(recovery_checkpoint),
            PackageStartupTestSeams::deterministic(launcher, None),
        )
    }

    fn spawn_deterministic_startup_failure_recovery(
        scratch: PackageScratch,
        backend: PackageSessionBackend,
        suite_budget: PackageDeterministicSuiteLease,
    ) -> Result<Self, Box<dyn Error>> {
        let executable = install_packaged_codex_provider_fixture(&scratch)?;
        let launcher = install_packaged_tui_launcher_fixture(&scratch)?;
        Self::spawn_configured(
            executable,
            scratch,
            backend,
            Some(RecoveryCheckpoint::RetainedRestorePending),
            PackageProviderSuiteBudget::Deterministic {
                _lease: suite_budget,
            },
            PackageInferenceExpectation::Zero,
            PackageStartupTestSeams::deterministic(
                launcher,
                Some(PackageStartupFault::TerminalChannelWriteRetainedStartupRestore),
            ),
        )
    }

    fn spawn_configured(
        executable: PathBuf,
        scratch: PackageScratch,
        backend: PackageSessionBackend,
        recovery_checkpoint: Option<RecoveryCheckpoint>,
        provider_suite_budget: PackageProviderSuiteBudget,
        inference_expectation: PackageInferenceExpectation,
        startup_seams: PackageStartupTestSeams,
    ) -> Result<Self, Box<dyn Error>> {
        let provider_target = provider_suite_budget.provider_target();
        let startup_fault = startup_seams.startup_fault;
        let (_placeholder_sender, placeholder_result) = mpsc::sync_channel(1);
        let mut harness = Self {
            _provider_suite_budget: provider_suite_budget,
            scratch: Some(scratch),
            backend: Some(backend),
            coordinator: None,
            completion: None,
            provider_target,
            startup_fault,
            inference_expectation,
            recovery_checkpoint,
            recovery_request_state: PackageRecoveryRequestState::Available,
            generation_cleanup: None,
            generation_deadline_fence: None,
            guardian_startup_arm_observed: false,
            master: None,
            initial_termios: None,
            output_cancel: None,
            output_result: placeholder_result,
            startup_sentinel_observed: None,
            response_sentinel_observed: None,
            output_worker: None,
            output_finished: false,
            last_handoff_probe_phase: None,
            recovery_failure_evidence: PackageRecoveryFailureEvidence::default(),
            last_fixed_failure_detail: None,
            last_fixed_cleanup_failure_detail: None,
        };
        let mut setup_phase = PackageHarnessSetupPhase::Filesystem;
        let setup = (|| -> Result<(), Box<dyn Error>> {
            let scratch = harness
                .scratch
                .as_ref()
                .ok_or("package supervisor scratch was missing")?;
            let report_root = scratch.root.join("supervisor-report");
            let runtime_parent = scratch.root.join("r");
            private_directory(&report_root)?;
            private_directory(&runtime_parent)?;
            setup_phase = PackageHarnessSetupPhase::RuntimeParentValidation;
            validate_packaged_runtime_parent(&runtime_parent)?;
            setup_phase = PackageHarnessSetupPhase::PtyOpen;
            let owner = PtyOwner::open(PACKAGE_SUPERVISOR_INITIAL_SIZE)?;
            setup_phase = PackageHarnessSetupPhase::CommandBuild;
            let mut command = package_supervisor_helper_command(
                PACKAGE_SUPERVISOR_COORDINATOR_ROLE,
                scratch,
                &executable,
                harness
                    .backend
                    .as_ref()
                    .ok_or("package session backend was missing")?
                    .address(),
                recovery_checkpoint,
                provider_target,
                &startup_seams,
            )?;
            setup_phase = PackageHarnessSetupPhase::PtyConfiguration;
            let master = owner.configure_child(&mut command)?;
            master.enable_nonblocking()?;
            harness.initial_termios = Some(rustix::termios::tcgetattr(&master)?);

            setup_phase = PackageHarnessSetupPhase::OutputWorker;
            let output_descriptor = rustix::io::fcntl_dupfd_cloexec(master.as_fd(), 3)?;
            let (output_cancel, cancellation) = mpsc::sync_channel(1);
            let (output_sender, output_result) = mpsc::sync_channel(1);
            // This bounded one-shot remains entirely in the package parent.
            // It is never projected into a Command and cannot become inherited
            // recovery, process, filesystem, or socket authority.
            let (startup_sentinel_sender, startup_sentinel_observed) = mpsc::sync_channel(1);
            let (response_sentinel_sender, response_sentinel_observed) = mpsc::sync_channel(1);
            let output_worker = thread::Builder::new()
                .name("calcifer-package-official-tui-output".to_owned())
                .spawn(move || {
                    let result = drain_package_pty_output(
                        File::from(output_descriptor),
                        cancellation,
                        startup_sentinel_sender,
                        response_sentinel_sender,
                    );
                    let _ = output_sender.send(result);
                })?;
            harness.output_cancel = Some(output_cancel);
            harness.output_result = output_result;
            harness.startup_sentinel_observed = Some(startup_sentinel_observed);
            harness.response_sentinel_observed = Some(response_sentinel_observed);
            harness.output_worker = Some(output_worker);
            harness.master = Some(master);

            setup_phase = PackageHarnessSetupPhase::CompletionAuthority;
            let (completion, transit) = CompletionPair::new()?.split();
            harness.completion = Some(completion);
            setup_phase = PackageHarnessSetupPhase::GenerationFence;
            let generation_deadline_fence = PackageGenerationDeadlineFence::starting_at_for_target(
                Instant::now(),
                provider_target,
            )
            .map_err(|_| "package generation deadline fence overflowed")?;
            if generation_deadline_fence.external_fence
                > harness
                    .backend
                    .as_ref()
                    .ok_or("package session backend was missing")?
                    .deadline()
            {
                return Err("package backend did not cover the generation fence".into());
            }
            setup_phase = PackageHarnessSetupPhase::CoordinatorSpawn;
            let child = match calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(
                command,
                transit.as_fd(),
            ) {
                Ok(child) => child,
                Err(failure) => {
                    if let Some(started) = failure.into_started_child() {
                        harness.coordinator = Some(started.into_child());
                        harness.generation_cleanup =
                            Some(PackageGenerationCleanupEvidence::default());
                        harness.generation_deadline_fence = Some(generation_deadline_fence);
                    }
                    return Err("package coordinator spawn failed".into());
                }
            };
            drop(transit);
            harness.coordinator = Some(child);
            harness.generation_cleanup = Some(PackageGenerationCleanupEvidence::default());
            harness.generation_deadline_fence = Some(generation_deadline_fence);
            setup_phase = PackageHarnessSetupPhase::InitialPtyWrite;
            write_package_pty_input(
                harness.master()?,
                PACKAGE_SUPERVISOR_PRE_READY_INPUT,
                Instant::now() + IO_TIMEOUT,
            )?;
            Ok(())
        })();
        harness.finish_setup(setup, setup_phase)
    }

    /// Compatibility wrapper for the checksum-pinned retained-recovery case.
    fn request_selected_recovery(&mut self) -> Result<(), Box<dyn Error>> {
        self.trigger_selected_recovery(PackageRecoveryTrigger::GenerationBoundRequest)
    }

    /// Drives the selected package-only lifecycle phase, consumes its exact
    /// observation frame, then activates recovery through either the sole
    /// generation-bound CFRCR request or an empty owner write-half EOF. The
    /// local state is consumed before either transport attempt, so later
    /// cleanup can observe completion but cannot issue a second command.
    fn trigger_selected_recovery(
        &mut self,
        trigger: PackageRecoveryTrigger,
    ) -> Result<(), Box<dyn Error>> {
        let checkpoint = self
            .recovery_checkpoint
            .ok_or("package recovery checkpoint was not selected")?;
        let report = self.root()?.join("supervisor-report");
        self.observe_guardian_startup_arm(&report)?;
        let fence = self
            .generation_deadline_fence
            .ok_or("package generation deadline fence was missing")?;
        let checkpoint_deadline = fence
            .recovery_checkpoint_deadline(Instant::now())
            .map_err(|_| "package recovery checkpoint reached the generation recovery fence")?;
        let drive_result =
            self.drive_to_selected_recovery_checkpoint(checkpoint, checkpoint_deadline);
        if let Some(error) = drive_result.as_ref().err() {
            self.recovery_failure_evidence
                .snapshot_error(error.as_ref());
        }
        if drive_result.is_ok() {
            record_package_recovery_verification_phase(
                &report,
                PackageRecoveryVerificationPhase::CheckpointDriven,
            );
        }
        let fixed_startup_failure_observed = drive_result.as_ref().err().is_some_and(|error| {
            error
                .downcast_ref::<PackageRecoveryStartupDriveFailure>()
                .is_some()
        });
        let checkpoint_wait_deadline = if drive_result.is_err() {
            Instant::now()
                .checked_add(PACKAGE_SELECTED_RECOVERY_RECONCILIATION_TIMEOUT)
                .map(|deadline| deadline.min(checkpoint_deadline))
                .unwrap_or(checkpoint_deadline)
        } else {
            checkpoint_deadline
        };
        // An exact fixed startup failure is already earlier than the selected
        // lifecycle checkpoint. Feeding a guaranteed checkpoint timeout into
        // the completion decoder would terminalize that owner and make the
        // one permitted reverse recovery write impossible. The caller already
        // supplied recovery authority; the marker only short-circuits this
        // observation wait and never authorizes activation by itself.
        let checkpoint_result = if fixed_startup_failure_observed {
            Ok(())
        } else {
            let completion = self
                .completion
                .as_mut()
                .ok_or("package completion owner was missing")?;
            let coordinator = self
                .coordinator
                .as_mut()
                .ok_or("package coordinator child was missing")?;
            completion.await_test_checkpoint_while_peer_live(
                checkpoint,
                checkpoint_wait_deadline,
                || {
                    coordinator
                        .try_wait()
                        .map(|status| status.is_none())
                        .map_err(|_| CompletionError::Io)
                },
            )
        };
        if !fixed_startup_failure_observed {
            if let Err(error) = checkpoint_result {
                record_package_diagnostic_marker(
                    &report,
                    package_checkpoint_wait_failure_marker(error),
                );
            } else {
                record_package_recovery_verification_phase(
                    &report,
                    PackageRecoveryVerificationPhase::CheckpointVerified,
                );
            }
        }
        let observation_result = (!fixed_startup_failure_observed && checkpoint_result.is_ok())
            .then(|| self.prove_selected_checkpoint_is_observation_only());
        if observation_result.as_ref().is_some_and(Result::is_ok) {
            record_package_recovery_verification_phase(
                &report,
                PackageRecoveryVerificationPhase::ObservationOnlyVerified,
            );
        }

        let request_deadline = Instant::now()
            .checked_add(PACKAGE_CLEANUP_RECOVERY_REQUEST_TIMEOUT)
            .map(|deadline| deadline.min(fence.cleanup_fence))
            .ok_or("package recovery request deadline overflowed")?;
        // Once a selected checkpoint is valid, no diagnostic or drive error
        // may bypass the sole activation attempt. Return the earliest causal
        // error only after that one-shot boundary has been consumed.
        let result = activate_selected_recovery_after_drive(
            drive_result,
            checkpoint_result,
            observation_result,
            || match trigger {
                PackageRecoveryTrigger::GenerationBoundRequest => {
                    let request_result = PackageGenerationCleanupOperations::request_recovery_once(
                        self,
                        request_deadline,
                    );
                    if matches!(request_result, Ok(PackageRecoveryRequestObservation::Sent)) {
                        record_package_recovery_verification_phase(
                            &report,
                            PackageRecoveryVerificationPhase::RequestSent,
                        );
                    }
                    match request_result {
                        Ok(PackageRecoveryRequestObservation::Sent) => Ok(()),
                        Ok(PackageRecoveryRequestObservation::AttemptConsumedBoundaryUnknown) => {
                            Err("package recovery request boundary was not confirmed".into())
                        }
                        Ok(PackageRecoveryRequestObservation::AlreadyConsumed) => {
                            Err("package recovery request was already consumed".into())
                        }
                        Err(error) => Err(error.into()),
                    }
                }
                PackageRecoveryTrigger::OwnerEof => {
                    let result = self.shutdown_selected_recovery_owner(request_deadline);
                    if result.is_ok() {
                        record_package_recovery_verification_phase(
                            &report,
                            PackageRecoveryVerificationPhase::OwnerWriteShutdown,
                        );
                    }
                    result
                }
            },
        );
        self.snapshot_recovery_secondary_failure();
        result
    }

    fn observe_guardian_startup_arm(&mut self, report: &Path) -> Result<(), Box<dyn Error>> {
        if self.guardian_startup_arm_observed {
            return Ok(());
        }
        let fence = self
            .generation_deadline_fence
            .ok_or("package generation deadline fence was missing")?;
        let observation_deadline = fence
            .guardian_startup_arm_observation_deadline()
            .map_err(|_| "package Guardian arm observation had no safe budget")?;
        wait_for_private_marker(
            &report.join(PACKAGED_GUARDIAN_STARTUP_ARMED_MARKER),
            b"armed\n",
            observation_deadline,
        )?;
        let observed_at = Instant::now();
        self.generation_deadline_fence = Some(
            fence
                .after_guardian_startup_armed(observed_at)
                .map_err(|_| "package Guardian armed too late for bounded recovery")?,
        );
        self.guardian_startup_arm_observed = true;
        record_package_diagnostic_marker(report, "recovery.guardian-startup-arm-observed");
        Ok(())
    }

    fn shutdown_selected_recovery_owner(
        &mut self,
        deadline: Instant,
    ) -> Result<(), Box<dyn Error>> {
        if !self.recovery_request_state.begin_attempt() {
            return Err("package recovery activation was already consumed".into());
        }
        self.completion
            .as_mut()
            .ok_or_else(|| -> Box<dyn Error> { "package completion owner was missing".into() })?
            .shutdown_recovery_owner_write(deadline)
            .map_err(|_| "package owner write-half shutdown was not confirmed".into())
    }

    fn prove_selected_checkpoint_is_observation_only(&mut self) -> Result<(), Box<dyn Error>> {
        // `await_test_checkpoint_while_peer_live` already proved one exact
        // CFCP frame with no queued trailing byte. Polling the production
        // completion decoder here would add no authority and could poison the
        // endpoint before the one-shot CFRCR/EOF attempt. The independent
        // entry-layer protocol test proves that CFCP alone cannot authorize
        // guardian recovery.
        let report = self.root()?.join("supervisor-report");
        let exited = match self
            .coordinator
            .as_mut()
            .ok_or("package coordinator child was missing")?
            .try_wait()
        {
            Ok(exited) => exited,
            Err(_) => {
                let failure = PackageRecoveryObservationFailure::CoordinatorWait;
                record_package_diagnostic_marker(&report, failure.marker());
                return Err(failure.into());
            }
        };
        if exited.is_some() {
            self.generation_cleanup_mut()?.exact_coordinator_wait = true;
            let failure = PackageRecoveryObservationFailure::CoordinatorExited;
            record_package_diagnostic_marker(&report, failure.marker());
            return Err(failure.into());
        }
        Ok(())
    }

    fn verify_selected_recovery_outcome(&mut self) -> Result<(), Box<dyn Error>> {
        if self.provider_target != PackageProviderTarget::DeterministicFixture {
            return Err("deterministic recovery verification used the official provider".into());
        }
        let checkpoint = self
            .recovery_checkpoint
            .ok_or("package recovery checkpoint was not selected")?;
        if self.recovery_request_state != PackageRecoveryRequestState::Consumed {
            return Err("package recovery activation remained reusable".into());
        }
        let fence = self
            .generation_deadline_fence
            .ok_or("package generation deadline fence was missing")?;
        if checkpoint == RecoveryCheckpoint::Suspended {
            PackageGenerationCleanupOperations::wake_exact_coordinator(self)?;
        }
        let deadline = Instant::now()
            .checked_add(PROCESS_TIMEOUT + PROCESS_TIMEOUT)
            .map(|deadline| deadline.min(fence.cleanup_fence))
            .ok_or("package deterministic verification deadline overflowed")?;
        let status = self.wait_for_exact_coordinator(deadline)?;
        if !status.success() {
            return Err(
                "package deterministic coordinator helper did not exit successfully".into(),
            );
        }
        let root = self.root()?.to_path_buf();
        let report = root.join("supervisor-report");
        record_package_recovery_verification_phase(
            &report,
            PackageRecoveryVerificationPhase::CoordinatorExited,
        );
        let projection =
            PackageCoordinatorReportProjection::selected(Some(checkpoint), self.startup_fault);
        wait_for_private_marker(
            &report.join("coordinator.report"),
            projection.marker(),
            deadline,
        )?;
        record_package_recovery_verification_phase(
            &report,
            PackageRecoveryVerificationPhase::ReportVerified,
        );
        self.verify_completion(deadline)?;
        record_package_recovery_verification_phase(
            &report,
            PackageRecoveryVerificationPhase::CompletionVerified,
        );
        for (name, phase) in [
            (
                "tui.child",
                PackageRecoveryVerificationPhase::TuiGroupAbsent,
            ),
            (
                "app.child",
                PackageRecoveryVerificationPhase::AppGroupAbsent,
            ),
            (
                "guardian.child",
                PackageRecoveryVerificationPhase::GuardianGroupAbsent,
            ),
        ] {
            if let Err(failure) = verify_reported_package_group_absent(&report, name, deadline) {
                record_package_diagnostic_marker(&report, failure.marker());
                return Err(failure.into());
            }
            record_package_recovery_verification_phase(&report, phase);
        }
        self.generation_cleanup_mut()?.reported_groups_absent = true;
        record_package_recovery_verification_phase(
            &report,
            PackageRecoveryVerificationPhase::ReportedGroupsAbsent,
        );
        verify_package_build_namespaces_empty(&root)?;
        self.generation_cleanup_mut()?.runtime_empty = true;
        record_package_recovery_verification_phase(
            &report,
            PackageRecoveryVerificationPhase::RuntimeEmpty,
        );
        Ok(())
    }

    fn verify_selected_recovery_trigger(
        &self,
        trigger: PackageRecoveryTrigger,
    ) -> Result<(), Box<dyn Error>> {
        let report = self.root()?.join("supervisor-report");
        let (required, forbidden): (&[&str], &[&str]) = match trigger {
            PackageRecoveryTrigger::GenerationBoundRequest => (
                &[
                    "recovery.request-sent",
                    "recovery.guardian-checkpoint.request-verified",
                ],
                &[
                    "recovery.owner-write-shutdown",
                    "recovery.guardian-checkpoint.owner-lost",
                    "recovery.guardian-checkpoint.protocol-rejected-owner-lost",
                ],
            ),
            PackageRecoveryTrigger::OwnerEof => (
                &[
                    "recovery.owner-write-shutdown",
                    "recovery.guardian-checkpoint.owner-lost",
                ],
                &[
                    "recovery.request-sent",
                    "recovery.guardian-checkpoint.request-verified",
                    "recovery.guardian-checkpoint.protocol-rejected-owner-lost",
                ],
            ),
        };
        for marker in required {
            if !report.join(marker).is_file() {
                return Err("package recovery activation omitted its exact cause proof".into());
            }
        }
        for marker in forbidden
            .iter()
            .copied()
            .chain(["guardian-recovery.retained"])
        {
            if report.join(marker).exists() {
                return Err("package recovery activation admitted a conflicting cause".into());
            }
        }
        Ok(())
    }

    fn drive_to_selected_recovery_checkpoint(
        &mut self,
        checkpoint: RecoveryCheckpoint,
        deadline: Instant,
    ) -> Result<(), Box<dyn Error>> {
        let report = self.root()?.join("supervisor-report");
        match checkpoint {
            RecoveryCheckpoint::StartupQueued => {
                wait_for_package_child_marker(&report.join("tui.child"), deadline)?;
            }
            RecoveryCheckpoint::Ready => {
                wait_for_private_marker_while_child_live(
                    &report.join("initial-size.live"),
                    b"37 111\n",
                    wait_for_package_child_marker(&report.join("guardian.child"), deadline)?,
                    deadline,
                )?;
            }
            RecoveryCheckpoint::Active => {
                wait_for_private_marker(&report.join("initial-gate.live"), b"open\n", deadline)?;
            }
            RecoveryCheckpoint::Suspended => {
                wait_for_private_marker(&report.join("initial-gate.live"), b"open\n", deadline)?;
                wait_for_package_raw_mode(self.master()?, deadline)?;
                self.signal_live_coordinator(rustix::process::Signal::TSTP)?;
            }
            RecoveryCheckpoint::RetainedQuiescing
            | RecoveryCheckpoint::RetainedRestorePending
            | RecoveryCheckpoint::RetainedCleanupPending => {
                let complete_input_transcript = [
                    PACKAGE_SUPERVISOR_INITIAL_INPUT,
                    PACKAGE_SUPERVISOR_EXIT_INPUT,
                ]
                .concat();
                let initial_gate = wait_for_private_marker_or_fixed_startup_failure(
                    &report,
                    &report.join("initial-gate.live"),
                    b"open\n",
                    deadline,
                );
                classify_package_recovery_initial_gate(&report, initial_gate)?;
                let raw_mode = self
                    .master()
                    .and_then(|master| wait_for_package_raw_mode(master, deadline));
                classify_package_recovery_drive_stage(
                    &report,
                    PackageRecoveryDriveFailure::RawMode,
                    raw_mode,
                )?;
                classify_package_recovery_drive_stage(
                    &report,
                    PackageRecoveryDriveFailure::StartupSentinel,
                    self.wait_for_tui_startup_sentinel(deadline),
                )?;
                record_package_diagnostic_marker(
                    &report,
                    "recovery.drive.tui-startup-sentinel-observed",
                );
                let initial_input_write = self.master().and_then(|master| {
                    write_package_pty_input(master, PACKAGE_SUPERVISOR_INITIAL_INPUT, deadline)
                });
                classify_package_recovery_drive_stage(
                    &report,
                    PackageRecoveryDriveFailure::InitialInputWrite,
                    initial_input_write,
                )?;
                classify_package_recovery_drive_stage(
                    &report,
                    PackageRecoveryDriveFailure::InitialInputObservation,
                    wait_for_package_input_transcript(
                        &report.join("input.live"),
                        PACKAGE_SUPERVISOR_INITIAL_INPUT,
                        deadline,
                    ),
                )?;
                let inference = self
                    .backend
                    .as_ref()
                    .ok_or_else(|| -> Box<dyn Error> {
                        "package session backend was missing".into()
                    })
                    .and_then(|backend| backend.wait_for_inference_completion(deadline));
                classify_package_recovery_drive_stage(
                    &report,
                    PackageRecoveryDriveFailure::Inference,
                    inference,
                )?;
                record_package_diagnostic_marker(
                    &report,
                    "recovery.drive.backend-inference-completed",
                );
                // The backend acknowledgement proves one validated SSE stream
                // was flushed. This independent parent-side PTY observation
                // proves the official TUI rendered its fixed assistant text;
                // both must precede /quit so an in-flight turn cannot race the
                // retained recovery checkpoint.
                classify_package_recovery_drive_stage(
                    &report,
                    PackageRecoveryDriveFailure::ResponseSentinel,
                    self.wait_for_tui_response_sentinel(deadline),
                )?;
                record_package_diagnostic_marker(
                    &report,
                    "recovery.drive.tui-response-sentinel-observed",
                );
                let exit_input_write = self.master().and_then(|master| {
                    write_package_pty_input(master, PACKAGE_SUPERVISOR_EXIT_INPUT, deadline)
                });
                classify_package_recovery_drive_stage(
                    &report,
                    PackageRecoveryDriveFailure::ExitInputWrite,
                    exit_input_write,
                )?;
                classify_package_recovery_drive_stage(
                    &report,
                    PackageRecoveryDriveFailure::ExitInputObservation,
                    wait_for_package_input_transcript(
                        &report.join("input.live"),
                        &complete_input_transcript,
                        deadline,
                    ),
                )?;
            }
        }
        Ok(())
    }

    fn exercise(&mut self) -> Result<(), Box<dyn Error>> {
        let root = self.root()?.to_path_buf();
        let report = root.join("supervisor-report");
        let complete_input_transcript = [
            PACKAGE_SUPERVISOR_INITIAL_INPUT,
            PACKAGE_SUPERVISOR_EXIT_INPUT,
        ]
        .concat();
        let generation_fence = self
            .generation_deadline_fence
            .ok_or("package generation deadline fence was missing")?;
        let exercise_deadline = |requested_timeout| -> Result<Instant, Box<dyn Error>> {
            generation_fence
                .exercise_deadline(Instant::now(), requested_timeout)
                .map_err(|_| "package exercise reached the generation recovery fence".into())
        };
        let guardian = wait_for_package_child_marker(
            &report.join("guardian.child"),
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        wait_for_private_marker_while_child_live(
            &report.join("initial-size.live"),
            b"37 111\n",
            guardian,
            exercise_deadline(PACKAGE_SUPERVISOR_STARTUP_TIMEOUT)?,
        )?;
        let tui = wait_for_package_child_marker(
            &report.join("tui.child"),
            exercise_deadline(PACKAGE_SUPERVISOR_STARTUP_TIMEOUT)?,
        )?;
        let _app = wait_for_package_child_marker(
            &report.join("app.child"),
            exercise_deadline(PACKAGE_SUPERVISOR_STARTUP_TIMEOUT)?,
        )?;
        if let Err(failure) = validate_official_tui_group(tui, exercise_deadline(IO_TIMEOUT)?) {
            record_package_diagnostic_marker(&report, failure.marker());
            return Err(Box::new(failure));
        }
        record_package_exercise_phase(&report, PackageExercisePhase::ChildrenValidated);

        wait_for_private_marker(
            &report.join("initial-gate.live"),
            b"open\n",
            exercise_deadline(PACKAGE_SUPERVISOR_STARTUP_TIMEOUT)?,
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::InitialGateObserved);
        wait_for_package_raw_mode(self.master()?, exercise_deadline(IO_TIMEOUT)?)?;
        record_package_exercise_phase(&report, PackageExercisePhase::RawModeObserved);
        if let Err(failure) = validate_live_official_tui_group(tui, exercise_deadline(IO_TIMEOUT)?)
        {
            record_package_diagnostic_marker(&report, failure.marker());
            return Err(Box::new(failure));
        }
        record_package_exercise_phase(&report, PackageExercisePhase::PostGateTuiLive);
        let before_initial = read_private_bounded(&report.join("input.live"), 128 * 1024)?;
        if contains_bytes(&before_initial, PACKAGE_SUPERVISOR_PRE_READY_INPUT) {
            return Err("pre-ready input crossed the production input gate".into());
        }
        record_package_exercise_phase(&report, PackageExercisePhase::PreReadyInputBlocked);

        // Codex 0.144.x runs terminal capability probes after raw mode and
        // intentionally discards unrelated input observed during that
        // exclusive startup window. The seeded history is rendered only
        // after those probes finish, so this fixed parent-side observation is
        // the semantic boundary at which a user prompt can no longer be
        // consumed by startup probing.
        self.wait_for_tui_startup_sentinel(exercise_deadline(IO_TIMEOUT)?)?;
        record_package_exercise_phase(&report, PackageExercisePhase::StartupSentinelObserved);
        write_package_pty_input(
            self.master()?,
            PACKAGE_SUPERVISOR_INITIAL_INPUT,
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::InitialInputWritten);
        wait_for_package_input_transcript(
            &report.join("input.live"),
            PACKAGE_SUPERVISOR_INITIAL_INPUT,
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::InitialInputObserved);

        // The terminal-pump acknowledgement above proves only that bytes
        // crossed Calcifer's input gate. Wait for both the validated backend
        // response EOF and the independently rendered TUI sentinel before
        // exercising job control, so SIGTSTP cannot race the official TUI's
        // initial prompt handling.
        self.backend
            .as_ref()
            .ok_or("package session backend was missing")?
            .wait_for_inference_completion(exercise_deadline(IO_TIMEOUT)?)?;
        record_package_exercise_phase(&report, PackageExercisePhase::BackendInferenceCompleted);
        self.wait_for_tui_response_sentinel(exercise_deadline(IO_TIMEOUT)?)?;
        record_package_exercise_phase(&report, PackageExercisePhase::ResponseSentinelObserved);

        self.master()?.set_size(PACKAGE_SUPERVISOR_RESIZED_SIZE)?;
        // TIOCSWINSZ normally emits WINCH, but the explicit notification is
        // the portable delivery authority. The guardian makes an identical
        // resize idempotent, so Darwin's automatic signal cannot duplicate the
        // terminal mutation or its semantic observation.
        self.signal_live_coordinator(rustix::process::Signal::WINCH)?;
        wait_for_private_marker(
            &report.join("resize.live"),
            b"41 123\n",
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::ResizeObserved);

        self.signal_live_coordinator(rustix::process::Signal::TSTP)?;
        wait_for_private_marker(
            &report.join("suspend.live"),
            b"suspended\n",
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::SuspendObserved);
        let stopped_tui = classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::TuiStopWait,
            wait_for_stable_stopped_package_group(tui.pgid, exercise_deadline(IO_TIMEOUT)?),
        )?;
        if let Err(failure) = validate_stopped_official_tui_snapshot(
            tui,
            &stopped_tui,
            rustix::process::geteuid().as_raw(),
        ) {
            return classify_package_job_control_stage::<(), _>(
                &report,
                PackageJobControlFailure::TuiStoppedSnapshot(failure),
                Err(failure),
            );
        }
        let coordinator_group = classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::CoordinatorStopWait,
            self.coordinator_process_group(),
        )?;
        classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::CoordinatorStopWait,
            wait_for_stable_stopped_package_group(
                coordinator_group,
                exercise_deadline(IO_TIMEOUT)?,
            ),
        )?;
        let stopped_termios = classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::StoppedTermiosRead,
            self.master().and_then(|master| {
                rustix::termios::tcgetattr(master)
                    .map_err(|error| Box::new(error) as Box<dyn Error>)
            }),
        )?;
        let initial_termios = classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::StoppedTermiosSnapshotMissing,
            self.initial_termios.as_ref().cloned().ok_or(()),
        )?;
        if !termios_semantically_equal(&initial_termios, &stopped_termios) {
            return classify_package_job_control_stage::<(), _>(
                &report,
                PackageJobControlFailure::StoppedTermiosMismatch,
                Err(()),
            );
        }
        record_package_exercise_phase(&report, PackageExercisePhase::StoppedStateValidated);

        let input_before_suspended_write =
            read_private_bounded(&report.join("input.live"), 128 * 1024)?;
        classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::ResumeApply,
            self.master().and_then(|master| {
                master
                    .set_size(PACKAGE_SUPERVISOR_RESUMED_SIZE)
                    .map_err(|error| Box::new(error) as Box<dyn Error>)
            }),
        )?;
        write_package_pty_input(
            self.master()?,
            PACKAGE_SUPERVISOR_SUSPENDED_INPUT,
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        let observation_deadline = exercise_deadline(GRACE_OBSERVATION)?;
        thread::sleep(observation_deadline.saturating_duration_since(Instant::now()));
        if Instant::now() >= generation_fence.recovery_start {
            return Err("package exercise reached the generation recovery fence".into());
        }
        if read_private_bounded(&report.join("input.live"), 128 * 1024)?
            != input_before_suspended_write
        {
            return Err("terminal input progressed while the coordinator/TUI were stopped".into());
        }
        let stopped_again =
            wait_for_stable_stopped_package_group(tui.pgid, exercise_deadline(IO_TIMEOUT)?)?;
        if stopped_again != stopped_tui {
            return Err("official TUI group membership changed while stopped".into());
        }
        record_package_exercise_phase(&report, PackageExercisePhase::SuspendedInputBlocked);

        classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::ResumeApply,
            self.signal_live_coordinator(rustix::process::Signal::CONT),
        )?;
        classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::ResumeApply,
            wait_for_private_marker(
                &report.join("resume.live"),
                b"43 125\n",
                exercise_deadline(IO_TIMEOUT)?,
            ),
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::ResumeObserved);
        classify_package_job_control_stage(
            &report,
            PackageJobControlFailure::ResumeRearm,
            wait_for_private_marker(
                &report.join("resume-gate.live"),
                b"open\n",
                exercise_deadline(IO_TIMEOUT)?,
            ),
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::ResumeGateObserved);
        wait_for_package_raw_mode(self.master()?, exercise_deadline(IO_TIMEOUT)?)?;
        record_package_exercise_phase(&report, PackageExercisePhase::ResumeRawModeObserved);
        validate_resumed_official_tui_group(tui, &stopped_tui, exercise_deadline(IO_TIMEOUT)?)?;
        record_package_exercise_phase(&report, PackageExercisePhase::ResumeGroupValidated);
        let after_resume = read_private_bounded(&report.join("input.live"), 128 * 1024)?;
        if after_resume != input_before_suspended_write
            || contains_bytes(&after_resume, PACKAGE_SUPERVISOR_SUSPENDED_INPUT)
        {
            return Err("suspended input replayed through the fresh resume gate".into());
        }

        write_package_pty_input(
            self.master()?,
            PACKAGE_SUPERVISOR_EXIT_INPUT,
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::ExitInputWritten);
        wait_for_package_input_transcript(
            &report.join("input.live"),
            &complete_input_transcript,
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::ExitInputObserved);

        let status =
            self.wait_for_exact_coordinator(exercise_deadline(PROCESS_TIMEOUT + PROCESS_TIMEOUT)?)?;
        if !status.success() {
            return Err("production coordinator helper did not exit successfully".into());
        }
        record_package_exercise_phase(&report, PackageExercisePhase::CoordinatorExited);
        wait_for_private_marker(
            &report.join("coordinator.complete"),
            b"exact-production-report-and-guardian-wait\n",
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        self.verify_completion(exercise_deadline(IO_TIMEOUT)?)?;
        write_private_new(
            &report.join("completion.verified"),
            b"exact-frame-and-eof\n",
        )?;
        record_package_exercise_phase(&report, PackageExercisePhase::CompletionVerified);

        let observation_bytes = wait_for_private_file(
            &report.join("session-observation.json"),
            128 * 1024,
            exercise_deadline(IO_TIMEOUT)?,
        )?;
        let observation: PackagedSessionObservation = serde_json::from_slice(&observation_bytes)?;
        if let Err(failure) =
            validate_package_session_observation(&observation, &complete_input_transcript)
        {
            record_package_diagnostic_marker(&report, failure.marker());
            return Err(Box::new(failure));
        }
        record_package_exercise_phase(&report, PackageExercisePhase::SessionObservationVerified);

        let output = self.finish_output_drain(exercise_deadline(IO_TIMEOUT)?)?;
        if !output.eof || output.total_bytes == 0 || !output.response_sentinel_seen {
            return Err("outer PTY did not observe official TUI output followed by EOF".into());
        }
        record_package_exercise_phase(&report, PackageExercisePhase::OutputDrainVerified);
        let restored = rustix::termios::tcgetattr(self.master()?)?;
        if !termios_semantically_equal(&initial_termios, &restored)
            || self.master()?.size()? != PACKAGE_SUPERVISOR_RESUMED_SIZE
        {
            return Err("outer PTY was not restored after exact coordinator completion".into());
        }
        record_package_exercise_phase(&report, PackageExercisePhase::TerminalRestored);
        verify_reported_package_groups_absent(&report, exercise_deadline(IO_TIMEOUT)?)?;
        self.generation_cleanup_mut()?.reported_groups_absent = true;
        verify_package_build_namespaces_empty(&root)?;
        self.generation_cleanup_mut()?.runtime_empty = true;
        Ok(())
    }

    fn generation_cleanup_mut(
        &mut self,
    ) -> Result<&mut PackageGenerationCleanupEvidence, Box<dyn Error>> {
        self.generation_cleanup
            .as_mut()
            .ok_or_else(|| "package coordinator generation was not started".into())
    }

    fn coordinator_process_group(&self) -> Result<i32, Box<dyn Error>> {
        let child = self
            .coordinator
            .as_ref()
            .ok_or("package coordinator child was missing")?;
        if self
            .generation_cleanup
            .is_some_and(|evidence| evidence.exact_coordinator_wait)
        {
            return Err("package coordinator was already reaped".into());
        }
        i32::try_from(child.id()).map_err(Into::into)
    }

    /// Sends only to the exact, still-unreaped direct coordinator child. Child
    /// report files remain observations and can never select a signal target.
    fn signal_live_coordinator(
        &mut self,
        signal: rustix::process::Signal,
    ) -> Result<(), Box<dyn Error>> {
        let child = self
            .coordinator
            .as_mut()
            .ok_or("package coordinator child was missing")?;
        if child.try_wait()?.is_some() {
            self.generation_cleanup_mut()?.exact_coordinator_wait = true;
            return Err("package coordinator exited before the requested signal".into());
        }
        let pid = rustix::process::Pid::from_child(&*child);
        rustix::process::kill_process(pid, signal)?;
        Ok(())
    }

    fn wait_for_exact_coordinator(
        &mut self,
        deadline: Instant,
    ) -> Result<std::process::ExitStatus, Box<dyn Error>> {
        let status = wait_for_package_child(
            self.coordinator
                .as_mut()
                .ok_or("package coordinator child was missing")?,
            deadline,
        )?;
        self.generation_cleanup_mut()?.exact_coordinator_wait = true;
        Ok(status)
    }

    fn verify_completion(&mut self, deadline: Instant) -> Result<(), PackageCleanupFailure> {
        if self
            .generation_cleanup
            .is_some_and(|evidence| evidence.completion_verified)
        {
            return Ok(());
        }
        let completion = self
            .completion
            .as_mut()
            .ok_or(PackageCleanupFailure::CompletionBoundary)?;
        loop {
            match completion
                .poll_once()
                .map_err(|_| PackageCleanupFailure::CompletionBoundary)?
            {
                CompletionPoll::Verified => break,
                CompletionPoll::RetainedUnrecoverable => {
                    return Err(PackageCleanupFailure::RetainedUnrecoverable);
                }
                CompletionPoll::Pending if Instant::now() < deadline => thread::yield_now(),
                CompletionPoll::Pending => {
                    return Err(PackageCleanupFailure::CompletionProof);
                }
            }
        }
        self.completion.take();
        self.generation_cleanup_mut()
            .map_err(|_| PackageCleanupFailure::CompletionProof)?
            .completion_verified = true;
        Ok(())
    }

    fn master(&self) -> Result<&PtyMaster, Box<dyn Error>> {
        self.master
            .as_ref()
            .ok_or_else(|| "package outer PTY master was missing".into())
    }

    fn root(&self) -> Result<&Path, Box<dyn Error>> {
        self.scratch
            .as_ref()
            .map(|scratch| scratch.root.as_path())
            .ok_or_else(|| "package supervisor scratch was missing".into())
    }

    fn latest_fixed_phase(&self) -> &'static str {
        let Some(root) = self.scratch.as_ref().map(|scratch| &scratch.root) else {
            return "scratch-missing";
        };
        let report = root.join("supervisor-report");
        Self::latest_fixed_phase_from_report(&report)
    }

    fn latest_fixed_failure_detail(&self) -> Option<&'static str> {
        self.recovery_failure_evidence.primary_marker().or_else(|| {
            self.scratch
                .as_ref()
                .and_then(|scratch| {
                    Self::latest_fixed_failure_detail_from_report(
                        &scratch.root.join("supervisor-report"),
                    )
                })
                .or(self.last_fixed_failure_detail)
        })
    }

    fn snapshot_recovery_secondary_failure(&mut self) {
        let primary = self.recovery_failure_evidence.primary_marker();
        let drive_context = self
            .recovery_failure_evidence
            .drive_context()
            .map(PackageRecoveryDriveFailure::marker);
        let candidate = self
            .scratch
            .as_ref()
            .and_then(|scratch| {
                Self::latest_fixed_failure_detail_from_report_excluding(
                    &scratch.root.join("supervisor-report"),
                    primary,
                    drive_context,
                )
            })
            .or_else(|| {
                self.last_fixed_failure_detail
                    .filter(|marker| Some(*marker) != primary && Some(*marker) != drive_context)
            });
        self.recovery_failure_evidence.snapshot_secondary(candidate);
    }

    fn latest_fixed_secondary_failure_detail(&self) -> Option<&'static str> {
        self.recovery_failure_evidence.secondary_marker()
    }

    fn latest_fixed_cleanup_failure_detail(&self) -> Option<&'static str> {
        self.last_fixed_cleanup_failure_detail
    }

    fn latest_handoff_probe_phase(&self) -> Option<PackageHandoffProbePhase> {
        self.last_handoff_probe_phase
    }

    fn latest_fixed_failure_or_phase_from_report(report: &Path) -> &'static str {
        Self::latest_fixed_failure_detail_from_report(report)
            .unwrap_or_else(|| Self::latest_fixed_phase_from_report(report))
    }

    fn latest_fixed_failure_detail_from_report(report: &Path) -> Option<&'static str> {
        Self::latest_fixed_failure_detail_from_report_excluding(report, None, None)
    }

    fn latest_fixed_failure_detail_from_report_excluding(
        report: &Path,
        primary: Option<&'static str>,
        drive_context: Option<&'static str>,
    ) -> Option<&'static str> {
        Self::fixed_failure_catalog().find(|marker| {
            Some(*marker) != primary
                && Some(*marker) != drive_context
                && fixed_package_failure_marker_is_valid(report, marker)
        })
    }

    fn fixed_failure_catalog() -> impl Iterator<Item = &'static str> {
        PACKAGED_COMPATIBILITY_FAILURE_MARKERS
            .iter()
            .copied()
            .chain(PACKAGED_APP_SOCKET_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGED_SESSION_STARTUP_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGE_JOB_CONTROL_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGE_OFFICIAL_TUI_GROUP_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGE_SESSION_OBSERVATION_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGE_NETWORK_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGED_STARTUP_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGED_SESSION_RETAINED_OPERATION_MARKERS.iter().copied())
            .chain(PACKAGE_RECOVERY_OBSERVATION_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGE_RECOVERY_DRIVE_FAILURE_MARKERS.iter().copied())
            .chain(PACKAGE_SESSION_BACKEND_FAILURE_MARKERS.iter().copied())
            .chain([
                "app-fixture.handshake-worker-failed",
                "app-fixture.worker-failed",
                "tui-fixture.inference-failed",
                "guardian-retained.termination-cause.natural-tui-eof",
                "guardian-retained.termination-cause.coordinator-stop",
                "guardian-retained.termination-cause.forwarded-hup",
                "guardian-retained.termination-cause.forwarded-term",
                "guardian-retained.termination-cause.none",
                "recovery.checkpoint-failed.create",
                "recovery.checkpoint-failed.descriptor",
                "recovery.checkpoint-failed.inherited",
                "recovery.checkpoint-failed.io",
                "recovery.checkpoint-failed.missing-frame",
                "recovery.checkpoint-failed.invalid-frame",
                "recovery.checkpoint-failed.trailing-data",
                "recovery.checkpoint-failed.deadline",
                "recovery.checkpoint-failed.peer-exited",
                "recovery.checkpoint-failed.replay",
                "recovery.checkpoint-failed.too-late",
                "startup-failure.session-readiness",
                "guardian-recovery.retained",
            ])
    }

    fn latest_fixed_phase_from_report(report: &Path) -> &'static str {
        for phase in PACKAGE_RECOVERY_VERIFICATION_PHASES.iter().rev().copied() {
            if report.join(phase.marker()).is_file() {
                return phase.marker();
            }
        }
        if report.join("guardian-retained").is_file() {
            return "guardian-retained";
        }
        for phase in PACKAGE_EXERCISE_PHASES.iter().rev().copied() {
            if report.join(phase.marker()).is_file() {
                return phase.marker();
            }
        }
        for (name, phase) in [
            ("coordinator.complete", "coordinator-complete"),
            (
                "startup-failure.tui-launch.subtype.provider-timeout",
                "startup-failure-tui-launch-provider-timeout",
            ),
            (
                "startup-failure.tui-launch.state.before-spawn",
                "startup-failure-tui-launch-before-spawn",
            ),
            ("startup-failure.terminal", "startup-failure-terminal"),
            (
                "startup-failure.compatibility",
                "startup-failure-compatibility",
            ),
            (
                "startup-failure.runtime-create",
                "startup-failure-runtime-create",
            ),
            (
                "startup-failure.runtime-layout",
                "startup-failure-runtime-layout",
            ),
            ("startup-failure.runtime", "startup-failure-runtime"),
            ("startup-failure.app-plan", "startup-failure-app-plan"),
            ("startup-failure.app-launch", "startup-failure-app-launch"),
            ("startup-failure.app-socket", "startup-failure-app-socket"),
            (
                "startup-failure.monitor-connect",
                "startup-failure-monitor-connect",
            ),
            (
                "startup-failure.monitor-start",
                "startup-failure-monitor-start",
            ),
            ("startup-failure.relay-plan", "startup-failure-relay-plan"),
            ("startup-failure.relay-start", "startup-failure-relay-start"),
            ("startup-failure.tui-plan", "startup-failure-tui-plan"),
            ("startup-failure.tui-pty", "startup-failure-tui-pty"),
            ("startup-failure.tui-launch", "startup-failure-tui-launch"),
            (
                "startup-failure.tui-readiness",
                "startup-failure-tui-readiness",
            ),
            ("startup-failure.lifecycle", "startup-failure-lifecycle"),
            (
                "startup-failure.session-readiness",
                "startup-failure-session-readiness",
            ),
            ("startup-failure.deadline", "startup-failure-deadline"),
            ("completion.verified", "completion-verified"),
            ("resume-gate.live", "resume-gate-open"),
            ("resume.live", "tui-resumed"),
            ("suspend.live", "tui-suspended"),
            ("resize.live", "tui-resized"),
            ("initial-gate.live", "initial-gate-open"),
            ("initial-size.live", "initial-size-observed"),
            ("tui.child", "tui-started"),
            ("app.child", "app-started"),
            ("guardian.observer", "guardian-observer-armed"),
            ("guardian.entered", "guardian-entered"),
            ("guardian.profile", "guardian-profile-validated"),
            ("guardian.profile-id", "guardian-profile-id-validated"),
            ("guardian.binary", "guardian-binary-validated"),
            ("guardian.root", "guardian-root-validated"),
            ("guardian.child", "guardian-started"),
            ("coordinator.profile", "coordinator-profile-committed"),
            ("coordinator.resume", "coordinator-resume-prepared"),
            ("coordinator.auth", "coordinator-auth-written"),
            ("coordinator.entered", "coordinator-entered"),
        ] {
            if report.join(name).is_file() {
                return phase;
            }
        }
        "outer-pty-spawned"
    }

    fn finish_output_drain(
        &mut self,
        deadline: Instant,
    ) -> Result<PackageOutputDrain, Box<dyn Error>> {
        if self.output_finished {
            return Err("package PTY output drain was already consumed".into());
        }
        let timeout = deadline.saturating_duration_since(Instant::now());
        let result = self
            .output_result
            .recv_timeout(timeout)
            .map_err(|_| "package PTY output drain exceeded its deadline")??;
        if let Some(worker) = self.output_worker.take() {
            worker
                .join()
                .map_err(|_| "package PTY output worker panicked")?;
        }
        self.output_finished = true;
        self.output_cancel.take();
        self.last_handoff_probe_phase = result.handoff_probe_phase;
        Ok(result)
    }

    fn wait_for_tui_startup_sentinel(&mut self, deadline: Instant) -> Result<(), Box<dyn Error>> {
        let observation = self
            .startup_sentinel_observed
            .take()
            .ok_or("package TUI startup observation was unavailable")?;
        match observation.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(()) => Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(
                "package TUI did not render its fixed startup history before its deadline".into(),
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("package PTY output ended before startup history was rendered".into())
            }
        }
    }

    fn wait_for_tui_response_sentinel(&mut self, deadline: Instant) -> Result<(), Box<dyn Error>> {
        let observation = self
            .response_sentinel_observed
            .take()
            .ok_or("package TUI response observation was unavailable")?;
        match observation.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(()) => Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(
                "package TUI did not render the fixed assistant sentinel before its deadline"
                    .into(),
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(
                "package PTY output ended before the fixed assistant sentinel was rendered".into(),
            ),
        }
    }

    fn cleanup(&mut self) -> Result<(), Box<dyn Error>> {
        self.cleanup_with_network_verifier(verify_package_registry_network_hermeticity)
    }

    fn finish_setup(
        self,
        setup: Result<(), Box<dyn Error>>,
        setup_phase: PackageHarnessSetupPhase,
    ) -> Result<Self, Box<dyn Error>> {
        self.finish_setup_with_network_verifier(
            setup,
            setup_phase,
            verify_package_registry_network_hermeticity,
        )
    }

    fn finish_setup_with_network_verifier<Verifier>(
        mut self,
        setup: Result<(), Box<dyn Error>>,
        setup_phase: PackageHarnessSetupPhase,
        network_verifier: Verifier,
    ) -> Result<Self, Box<dyn Error>>
    where
        Verifier:
            FnOnce(&Path, std::net::SocketAddr) -> Result<(), PackageNetworkHermeticityFailure>,
    {
        let Err(_setup_error) = setup else {
            return Ok(self);
        };
        let generation_started = self.coordinator.is_some()
            || self.generation_cleanup.is_some()
            || self.generation_deadline_fence.is_some();
        let cleanup_outcome =
            self.cleanup_after_exercise_with_network_verifier(generation_started, network_verifier);
        let preserved_evidence_root = cleanup_outcome
            .preserved_evidence_root()
            .map(Path::to_path_buf);
        let cleanup_failed = cleanup_outcome.result.is_err();
        Err(Box::new(PackageHarnessSetupFailure {
            setup_phase,
            generation_started,
            cleanup_failed,
            cleanup_phase: self.latest_fixed_cleanup_failure_detail(),
            preserved_evidence_root,
        }))
    }

    fn cleanup_after_exercise(&mut self, exercise_failed: bool) -> PackageHarnessCleanupOutcome {
        self.cleanup_after_exercise_with_network_verifier(
            exercise_failed,
            verify_package_registry_network_hermeticity,
        )
    }

    fn cleanup_with_network_verifier<Verifier>(
        &mut self,
        network_verifier: Verifier,
    ) -> Result<(), Box<dyn Error>>
    where
        Verifier:
            FnOnce(&Path, std::net::SocketAddr) -> Result<(), PackageNetworkHermeticityFailure>,
    {
        self.cleanup_after_exercise_with_network_verifier(false, network_verifier)
            .result
    }

    fn cleanup_after_exercise_with_network_verifier<Verifier>(
        &mut self,
        exercise_failed: bool,
        network_verifier: Verifier,
    ) -> PackageHarnessCleanupOutcome
    where
        Verifier:
            FnOnce(&Path, std::net::SocketAddr) -> Result<(), PackageNetworkHermeticityFailure>,
    {
        // Freeze any already-published session evidence before cleanup can
        // add backend/network markers or consume the scratch owner.
        self.snapshot_recovery_secondary_failure();
        let backend_address = self.backend.as_ref().map(PackageSessionBackend::address);
        let generation_started = match (
            self.coordinator.is_some(),
            self.generation_cleanup.is_some(),
            self.generation_deadline_fence.is_some(),
        ) {
            (false, false, false) => {
                // No exec boundary was crossed. The locally-created completion
                // pair is inert and setup scratch can be removed directly.
                self.completion.take();
                false
            }
            (true, true, true) => {
                self.finish_started_generation_cleanup_or_exit();
                self.snapshot_recovery_secondary_failure();
                // A successful four-proof gate consumes this generation. This
                // also makes explicit cleanup followed by Drop idempotent.
                self.generation_cleanup.take();
                self.generation_deadline_fence.take();
                true
            }
            _ => self.fail_closed_unproven_generation_cleanup(),
        };
        let mut failures = PackageHarnessCleanupFailures::default();
        self.coordinator.take();
        let output_worker_started = self.output_cancel.is_some() || self.output_worker.is_some();
        if !self.output_finished && output_worker_started {
            if let Some(cancel) = self.output_cancel.take() {
                // A disconnected receiver means the worker already reached a
                // terminal result. The result channel and exact join below
                // remain the authority for success or failure.
                let _ = cancel.try_send(());
            }
            match self.output_result.recv_timeout(Duration::from_secs(2)) {
                Ok(Ok(drain)) => {
                    self.last_handoff_probe_phase = drain.handoff_probe_phase;
                }
                Ok(Err(error)) => failures.record("package PTY output drain", error.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => failures.record(
                    "package PTY output drain",
                    "package PTY output cleanup exceeded its deadline".into(),
                ),
                Err(mpsc::RecvTimeoutError::Disconnected) => failures.record(
                    "package PTY output drain",
                    "package PTY output result authority disappeared".into(),
                ),
            }
            self.output_finished = true;
            if let Some(worker) = self.output_worker.take() {
                if worker.join().is_err() {
                    failures.record(
                        "package PTY output worker",
                        "package PTY output worker panicked".into(),
                    );
                }
            }
        }
        self.master.take();
        if let Some(backend) = self.backend.take() {
            match backend.cancel_and_join_transport() {
                Ok(observation) => failures.record_result(
                    "package inference evidence",
                    require_package_generation_inference_evidence(
                        generation_started,
                        self.inference_expectation,
                        observation,
                    ),
                ),
                Err(error) => {
                    if let Some(failure) =
                        error.downcast_ref::<PackageSessionBackendTransportFailure>()
                    {
                        if let Some(scratch) = self.scratch.as_ref() {
                            record_package_diagnostic_marker(
                                &scratch.root.join("supervisor-report"),
                                failure.marker,
                            );
                        }
                        self.last_fixed_failure_detail.get_or_insert(failure.marker);
                        self.last_fixed_cleanup_failure_detail
                            .get_or_insert(failure.marker);
                    }
                    failures.record("package session backend transport", error);
                }
            }
        }
        if let Err(failure) = run_package_network_hermeticity_gate(
            generation_started,
            self.provider_target,
            self.scratch.as_ref().map(|scratch| scratch.root.as_path()),
            backend_address,
            network_verifier,
        ) {
            if let Some(scratch) = self.scratch.as_ref() {
                record_package_diagnostic_marker(
                    &scratch.root.join("supervisor-report"),
                    failure.marker(),
                );
            }
            self.last_fixed_failure_detail
                .get_or_insert(failure.marker());
            self.last_fixed_cleanup_failure_detail
                .get_or_insert(failure.marker());
            failures.record("package network hermeticity", Box::new(failure));
        }
        if self.last_fixed_failure_detail.is_none() {
            self.last_fixed_failure_detail = self.scratch.as_ref().and_then(|scratch| {
                Self::latest_fixed_failure_detail_from_report(
                    &scratch.root.join("supervisor-report"),
                )
            });
        }
        self.snapshot_recovery_secondary_failure();
        // Preserve filesystem evidence after any failed started generation,
        // including a failure discovered only while draining PTY/backend/network
        // authorities. Pre-generation setup cleanup keeps its historical exact
        // deletion contract even when an injected cleanup operation fails.
        let preserve_evidence =
            exercise_failed || (generation_started && !failures.failures.is_empty());
        let scratch = match self.scratch.take() {
            Some(scratch) if preserve_evidence => match PreservedPackageEvidence::new(scratch) {
                Ok(evidence) => PackageScratchDisposition::Preserved(evidence),
                Err(error) => {
                    failures.record("package scratch evidence", error);
                    PackageScratchDisposition::Unavailable
                }
            },
            Some(scratch) => match scratch.cleanup() {
                Ok(()) => PackageScratchDisposition::Deleted,
                Err(error) => {
                    failures.record("package scratch", error);
                    PackageScratchDisposition::Unavailable
                }
            },
            None => PackageScratchDisposition::Unavailable,
        };
        PackageHarnessCleanupOutcome {
            result: failures.finish(),
            scratch,
        }
    }

    fn finish_started_generation_cleanup_or_exit(&mut self) {
        let Some(initial_evidence) = self.generation_cleanup else {
            self.fail_closed_unproven_generation_cleanup();
        };
        if initial_evidence.scratch_decision() == PackageScratchCleanupDecision::Delete {
            return;
        }
        let Some(fence) = self.generation_deadline_fence else {
            self.fail_closed_unproven_generation_cleanup();
        };
        let Ok(deadlines) = PackageCleanupDeadlines::within_generation(fence, Instant::now())
        else {
            self.fail_closed_unproven_generation_cleanup();
        };
        let Ok(driven_evidence) =
            drive_package_generation_cleanup(self, initial_evidence, deadlines)
        else {
            self.fail_closed_unproven_generation_cleanup();
        };
        if self.generation_cleanup != Some(driven_evidence)
            || driven_evidence.scratch_decision() != PackageScratchCleanupDecision::Delete
        {
            self.fail_closed_unproven_generation_cleanup();
        }
    }

    fn reap_exact_coordinator_for_cleanup(
        &mut self,
        term_deadline: Instant,
        kill_deadline: Instant,
    ) -> Result<(), Box<dyn Error>> {
        let child = self
            .coordinator
            .as_mut()
            .ok_or("package coordinator child was missing")?;
        if child.try_wait()?.is_none() {
            let pid = rustix::process::Pid::from_child(&*child);
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            while Instant::now() < term_deadline && child.try_wait()?.is_none() {
                thread::sleep(Duration::from_millis(10));
            }
            if child.try_wait()?.is_none() {
                child.kill()?;
                wait_for_package_child(child, kill_deadline)?;
            }
        }
        self.generation_cleanup_mut()?.exact_coordinator_wait = true;
        Ok(())
    }

    fn observe_exact_coordinator_state_for_cleanup(
        &mut self,
    ) -> Result<PackageExactCoordinatorStateObservation, Box<dyn Error>> {
        let (pid, reaped) = {
            let child = self
                .coordinator
                .as_mut()
                .ok_or("package coordinator child was missing")?;
            let pid = i32::try_from(child.id())?;
            let reaped = match child.try_wait() {
                Ok(Some(_)) => true,
                Ok(None) => false,
                // Observation failure proves neither liveness nor stopped
                // state. It grants no signal authority.
                Err(_) => return Ok(PackageExactCoordinatorStateObservation::NotProvenStopped),
            };
            (pid, reaped)
        };
        if reaped {
            self.generation_cleanup_mut()?.exact_coordinator_wait = true;
            return Ok(PackageExactCoordinatorStateObservation::Reaped);
        }

        let members = match package_process_group_snapshot(pid) {
            Ok(members) => members,
            Err(_) => return Ok(PackageExactCoordinatorStateObservation::NotProvenStopped),
        };
        let current_user = rustix::process::geteuid().as_raw();
        Ok(classify_exact_coordinator_snapshot(
            pid,
            current_user,
            &members,
        ))
    }

    fn fail_closed_unproven_generation_cleanup(&mut self) -> ! {
        // This module exists only in a libtest build. Production retains the
        // exact owners indefinitely; a test process must instead fail
        // terminally while those owners are still live so a hosted job cannot
        // hide the fixed diagnostic behind its outer timeout. The audited
        // `_exit`/`_Exit` boundary runs no Rust or C destructors and produces
        // no crash dump, authorizes no marker-derived signal or deletion, and
        // closes this process's complete descriptor table at one kernel
        // boundary.
        self.snapshot_recovery_secondary_failure();
        {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "package-generation-cleanup-unproven:phase={},failure={},secondary={}",
                self.latest_fixed_phase(),
                self.latest_fixed_failure_detail().unwrap_or("unclassified"),
                self.latest_fixed_secondary_failure_detail()
                    .unwrap_or("none")
            );
            let _ = stderr.flush();
        }
        calcifer_unix_child_fd::exit_process_without_destructors(
            PACKAGE_UNPROVEN_CLEANUP_EXIT_CODE,
        );
    }
}

impl PackageGenerationCleanupOperations for OfficialTuiPackageHarness {
    fn poll_normal_completion(
        &mut self,
        deadline: Instant,
    ) -> Result<PackageCompletionObservation, PackageCleanupFailure> {
        let completion = self
            .completion
            .as_mut()
            .ok_or(PackageCleanupFailure::CompletionBoundary)?;
        loop {
            match completion.poll_once() {
                Ok(CompletionPoll::Verified) => {
                    return Ok(PackageCompletionObservation::Verified);
                }
                Ok(CompletionPoll::RetainedUnrecoverable) => {
                    return Ok(PackageCompletionObservation::RetainedUnrecoverable);
                }
                Ok(CompletionPoll::Pending) if Instant::now() < deadline => {
                    thread::yield_now();
                }
                Ok(CompletionPoll::Pending) => {
                    return Ok(PackageCompletionObservation::Pending);
                }
                Err(_) => return Ok(PackageCompletionObservation::Rejected),
            }
        }
    }

    fn request_recovery_once(
        &mut self,
        deadline: Instant,
    ) -> Result<PackageRecoveryRequestObservation, PackageCleanupFailure> {
        if self.completion.is_none() {
            return Err(PackageCleanupFailure::RecoveryBoundary);
        }
        if !self.recovery_request_state.begin_attempt() {
            return Ok(PackageRecoveryRequestObservation::AlreadyConsumed);
        }
        let completion = self
            .completion
            .as_mut()
            .unwrap_or_else(|| std::process::abort());
        Ok(match completion.request_recovery(deadline) {
            Ok(()) => PackageRecoveryRequestObservation::Sent,
            // The request attempt is consumed on every error, but a failed
            // shutdown does not prove that the write half reached the kernel
            // close boundary. Preserve the healthy-lifecycle grace without
            // claiming a closure that was not observed.
            Err(_) => PackageRecoveryRequestObservation::AttemptConsumedBoundaryUnknown,
        })
    }

    fn observe_exact_coordinator_state(
        &mut self,
    ) -> Result<PackageExactCoordinatorStateObservation, PackageCleanupFailure> {
        self.observe_exact_coordinator_state_for_cleanup()
            .map_err(|_| PackageCleanupFailure::HealthyLifecycle)
    }

    fn wake_exact_coordinator(&mut self) -> Result<(), PackageCleanupFailure> {
        // Revalidate immediately before the signal. A stale or ambiguous
        // stopped observation must never turn a live coordinator's ordinary
        // next_active() transition into an unsolicited Continue command.
        if self
            .observe_exact_coordinator_state_for_cleanup()
            .map_err(|_| PackageCleanupFailure::HealthyLifecycle)?
            != PackageExactCoordinatorStateObservation::Stopped
        {
            return Ok(());
        }
        let child = self
            .coordinator
            .as_mut()
            .ok_or(PackageCleanupFailure::HealthyLifecycle)?;
        if child.try_wait().ok().flatten().is_none() {
            let pid = rustix::process::Pid::from_child(&*child);
            // This exact retained Child PID is the sole signal authority.
            // ESRCH or another signal error remains a readback problem for the
            // grace observer; it never authorizes a marker-derived fallback.
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::CONT);
        }
        Ok(())
    }

    fn observe_healthy_lifecycle(
        &mut self,
        mut completion_ready: bool,
        mut coordinator_reaped: bool,
        deadline: Instant,
    ) -> Result<PackageHealthyLifecycleObservation, PackageCleanupFailure> {
        loop {
            if !completion_ready {
                let completion = self
                    .completion
                    .as_mut()
                    .ok_or(PackageCleanupFailure::HealthyLifecycle)?;
                match completion.poll_once() {
                    Ok(CompletionPoll::Verified) => completion_ready = true,
                    Ok(CompletionPoll::RetainedUnrecoverable) => {
                        return Err(PackageCleanupFailure::RetainedUnrecoverable);
                    }
                    Ok(CompletionPoll::Pending) => {}
                    Err(_) => return Err(PackageCleanupFailure::CompletionBoundary),
                }
            }

            if !coordinator_reaped {
                let coordinator = self
                    .coordinator
                    .as_mut()
                    .ok_or(PackageCleanupFailure::HealthyLifecycle)?;
                if coordinator.try_wait().ok().flatten().is_some() {
                    coordinator_reaped = true;
                    self.generation_cleanup_mut()
                        .map_err(|_| PackageCleanupFailure::HealthyLifecycle)?
                        .exact_coordinator_wait = true;
                }
            }

            if completion_ready && coordinator_reaped {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(PackageHealthyLifecycleObservation {
            completion_ready,
            coordinator_reaped,
        })
    }

    fn force_reap_exact_coordinator(
        &mut self,
        term_deadline: Instant,
        kill_deadline: Instant,
    ) -> Result<(), PackageCleanupFailure> {
        self.reap_exact_coordinator_for_cleanup(term_deadline, kill_deadline)
            .map_err(|_| PackageCleanupFailure::ExactCoordinatorFallback)
    }

    fn prove_completion(&mut self, deadline: Instant) -> Result<(), PackageCleanupFailure> {
        self.verify_completion(deadline)
    }

    fn prove_reported_groups_absent(
        &mut self,
        deadline: Instant,
    ) -> Result<(), PackageCleanupFailure> {
        let root = self
            .scratch
            .as_ref()
            .map(|scratch| scratch.root.clone())
            .ok_or(PackageCleanupFailure::ReportedGroupsProof)?;
        verify_reported_package_groups_absent(&root.join("supervisor-report"), deadline)
            .map_err(|_| PackageCleanupFailure::ReportedGroupsProof)?;
        self.generation_cleanup_mut()
            .map_err(|_| PackageCleanupFailure::ReportedGroupsProof)?
            .reported_groups_absent = true;
        Ok(())
    }

    fn prove_runtime_empty(&mut self) -> Result<(), PackageCleanupFailure> {
        let root = self
            .scratch
            .as_ref()
            .map(|scratch| scratch.root.clone())
            .ok_or(PackageCleanupFailure::RuntimeProof)?;
        verify_package_build_namespaces_empty(&root)
            .map_err(|_| PackageCleanupFailure::RuntimeProof)?;
        self.generation_cleanup_mut()
            .map_err(|_| PackageCleanupFailure::RuntimeProof)?
            .runtime_empty = true;
        Ok(())
    }
}

impl Drop for OfficialTuiPackageHarness {
    fn drop(&mut self) {
        let started_generation = self.coordinator.is_some()
            || self.generation_cleanup.is_some()
            || self.generation_deadline_fence.is_some();
        // Explicit success/setup paths consume the harness through cleanup
        // before Drop. Reaching Drop with a started generation means an early
        // return or unwind; close every live authority but retain the validated
        // filesystem root for diagnosis. A pre-generation panic is retained as
        // well because an invariant failure is more valuable than its scratch.
        let outcome = self.cleanup_after_exercise(started_generation || thread::panicking());
        let mut stderr = io::stderr().lock();
        if let Err(error) = &outcome.result {
            let _ = writeln!(
                stderr,
                "package harness cleanup failed during drop: {error}"
            );
        }
        if let Some(root) = outcome.preserved_evidence_root() {
            let _ = writeln!(
                stderr,
                "package harness evidence preserved during drop at {}",
                root.display()
            );
        }
        let _ = stderr.flush();
    }
}

fn package_supervisor_helper_command(
    role: &str,
    scratch: &PackageScratch,
    executable: &Path,
    backend: std::net::SocketAddr,
    recovery_checkpoint: Option<RecoveryCheckpoint>,
    provider_target: PackageProviderTarget,
    startup_seams: &PackageStartupTestSeams,
) -> Result<Command, Box<dyn Error>> {
    let helper = fs::canonicalize(std::env::current_exe()?)?;
    let (launcher_environment, launcher) = match startup_seams.launcher_override.as_deref() {
        Some(launcher) => (
            PACKAGE_TUI_LAUNCHER_ENV,
            validate_package_launcher_for_target(provider_target, &scratch.root, launcher)?,
        ),
        None => super::launcher::packaged_launcher_executable_from_environment()?,
    };
    let mut command = Command::new(helper);
    command
        .env_clear()
        .args(["--exact", PACKAGE_SUPERVISOR_HELPER_TEST, "--nocapture"])
        .env(PACKAGE_SUPERVISOR_ROLE_ENV, role)
        .env(PACKAGE_SUPERVISOR_ROOT_ENV, &scratch.root)
        .env(PACKAGE_SUPERVISOR_BACKEND_ENV, backend.to_string())
        .env(PACKAGE_BINARY_ENV, executable)
        .env(launcher_environment, launcher)
        .env("HOME", &scratch.environment_home)
        .env("XDG_CONFIG_HOME", scratch.environment_home.join("config"))
        .env("XDG_DATA_HOME", scratch.environment_home.join("data"))
        .env("XDG_CACHE_HOME", scratch.environment_home.join("cache"))
        .env("XDG_RUNTIME_DIR", scratch.environment_home.join("run"))
        .env("TMPDIR", scratch.environment_home.join("tmp"))
        .env("TERM", "xterm-256color")
        .env(
            "PATH",
            std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
        )
        .current_dir(&scratch.workspace);
    project_package_recovery_checkpoint_environment(&mut command, recovery_checkpoint);
    project_package_provider_target_environment(&mut command, provider_target);
    project_package_startup_fault_environment(&mut command, startup_seams.startup_fault);
    Ok(command)
}

fn run_package_coordinator_helper() -> Result<(), Box<dyn Error>> {
    // Consume and reseal the parent-owned completion capability before this
    // helper creates any thread or child. It remains move-only until the exact
    // guardian exec below.
    let completion = CompletionTransit::take_inherited()?;
    let terminal = claim_controlling_terminal_from_stdin()?;
    if terminal.process() != terminal.process_group()
        || terminal.process() != terminal.session()
        || terminal.process() != terminal.foreground_process_group()
    {
        return Err("package coordinator did not own its controlling terminal".into());
    }
    let root = package_supervisor_root()?;
    let report_root = checked_package_subdirectory(&root, "supervisor-report")?;
    let runtime_parent = checked_package_subdirectory(&root, "r")?;
    let working_directory = checked_package_subdirectory(&root, "workspace")?;
    let environment_home = checked_package_subdirectory(&root, "environment")?;
    let provider_target = package_provider_target_from_environment()?;
    let startup_fault = validate_package_startup_fault_for_target(
        provider_target,
        package_startup_fault_from_environment()?,
    )?;
    let executable = package_provider_executable(provider_target, &root)?;
    let backend = package_supervisor_backend()?;
    let recovery_checkpoint = package_recovery_checkpoint_from_environment()?;
    if let Some(checkpoint) = recovery_checkpoint {
        write_private_atomic_new(
            &report_root.join(package_recovery_checkpoint_target_marker(checkpoint)),
            b"selected\n",
        )?;
    }
    write_private_new(&report_root.join("coordinator.entered"), b"entered\n")?;

    let registry = Registry::at(root.join("supervisor-registry"));
    let pending = registry.begin_codex_registration("official-tui-package")?;
    let pending_home = pending.home();
    write_package_registration_auth(&pending_home)?;
    write_private_new(&report_root.join("coordinator.auth"), b"written\n")?;
    let profile = pending.commit(CodexIdentityAdapter::for_test())?;
    let codex_home = fs::canonicalize(registry.profile_home(&profile)?)?;
    write_package_resume_rollout(&codex_home, &working_directory)?;
    write_private_new(&report_root.join("coordinator.resume"), b"prepared\n")?;
    let authority = registry.lock_profile_coordinator(&profile)?;
    let current = registry.refetch_by_id_under_lease(Provider::Codex, &profile.id)?;
    if current != profile {
        return Err("package coordinator profile identity changed under lease".into());
    }
    write_private_new(&report_root.join("coordinator.profile"), b"committed\n")?;

    let (coordinator_endpoint, guardian_endpoint) = TerminalChannelPair::new()?.split();
    let coordinator_terminal = CoordinatorTerminal::capture(io::stdin(), coordinator_endpoint)
        .map_err(|_| "package coordinator could not capture the outer terminal")?;
    let recovery = RecoveryTty::duplicate(io::stdin())?;
    let lifecycle_pair = LifecyclePair::new()?;

    let scratch_view = PackageScratchView {
        root: &root,
        workspace: &working_directory,
        environment_home: &environment_home,
    };
    let mut guardian_command = package_supervisor_helper_command_from_view(
        PACKAGE_SUPERVISOR_GUARDIAN_ROLE,
        &scratch_view,
        &executable,
        backend,
        recovery_checkpoint,
        provider_target,
        startup_fault,
    )?;
    guardian_command
        .env(PACKAGE_SUPERVISOR_CODEX_HOME_ENV, &codex_home)
        .env(PACKAGE_SUPERVISOR_PROFILE_ENV, &profile.id)
        .env(PACKAGE_SUPERVISOR_RUNTIME_ENV, &runtime_parent)
        .env(PACKAGE_SUPERVISOR_REPORT_ENV, &report_root)
        .env(
            PACKAGE_SUPERVISOR_FOREGROUND_ENV,
            terminal.foreground_process_group().to_string(),
        )
        .stdout(guardian_endpoint.into_stdio()?)
        .stderr(recovery.into_stdio()?)
        .process_group(0);
    let spawned = match spawn_guardian_with_lifecycle_stdin_and_completion(
        guardian_command,
        lifecycle_pair,
        completion.as_fd(),
    ) {
        Ok(spawned) => spawned,
        Err(failure) => {
            let (lifecycle, child, _error) = failure.into_parts();
            let Some(child) = child else {
                drop((authority, lifecycle, coordinator_terminal, completion));
                return Err("package guardian spawn failed before child start".into());
            };
            drop(completion);
            let coordinator = ProductionCoordinator::assemble(
                authority,
                child,
                lifecycle,
                coordinator_terminal,
                CoordinatorBounds::new(
                    PACKAGE_SUPERVISOR_STARTUP_TIMEOUT,
                    Duration::from_millis(20),
                )?,
            )
            .unwrap_or_else(|failure| {
                std::mem::forget(failure);
                loop {
                    thread::park();
                }
            });
            return match coordinator.run() {
                CoordinatorRunOutcome::Terminal(result) => {
                    drop(result.into_authority());
                    Err("package guardian spawn failed after child start".into())
                }
                CoordinatorRunOutcome::Retained(retained) => {
                    for marker in retained.packaged_marker_names() {
                        record_package_diagnostic_marker(&report_root, marker);
                    }
                    retained.park()
                }
            };
        }
    };
    let (guardian, lifecycle) = spawned.into_parts();
    drop(completion);
    let guardian_pid = i32::try_from(guardian.id())?;
    write_private_atomic_new(
        &report_root.join("guardian.child"),
        format!("{guardian_pid} {guardian_pid}\n").as_bytes(),
    )?;

    let coordinator = ProductionCoordinator::assemble(
        authority,
        guardian,
        lifecycle,
        coordinator_terminal,
        CoordinatorBounds::new(
            PACKAGE_SUPERVISOR_STARTUP_TIMEOUT,
            Duration::from_millis(20),
        )?,
    )
    .map_err(|_| "package production coordinator assembly failed")?;
    match coordinator.run() {
        CoordinatorRunOutcome::Terminal(result) => {
            let projection =
                PackageCoordinatorReportProjection::selected(recovery_checkpoint, startup_fault);
            let report = result.report();
            projection.require(result.guardian_status(), report)?;
            drop(result.into_authority());
            write_private_new(&report_root.join("coordinator.report"), projection.marker())?;
            if projection == PackageCoordinatorReportProjection::CompletedClean {
                write_private_new(
                    &report_root.join("coordinator.complete"),
                    b"exact-production-report-and-guardian-wait\n",
                )?;
            }
            Ok(())
        }
        CoordinatorRunOutcome::Retained(retained) => {
            for marker in retained.packaged_marker_names() {
                record_package_diagnostic_marker(&report_root, marker);
            }
            retained.park()
        }
    }
}

fn run_package_guardian_helper() -> Result<(), Box<dyn Error>> {
    // This is the second and final exec hop. Consume the inherited transit
    // capability before parsing package configuration or creating any worker,
    // then hand the exact endpoint to the shared production bootstrap core.
    let completion = CompletionTransit::take_inherited()?.into_guardian();
    let recovery_checkpoint = package_recovery_checkpoint_from_environment()?;
    let provider_target = package_provider_target_from_environment()?;
    let startup_fault = validate_package_startup_fault_for_target(
        provider_target,
        package_startup_fault_from_environment()?,
    )?;
    let root = package_supervisor_root()?;
    let (_, selected_launcher) = super::launcher::packaged_launcher_executable_from_environment()?;
    validate_package_launcher_for_target(provider_target, &root, &selected_launcher)?;
    let codex_home =
        checked_package_environment_path(PACKAGE_SUPERVISOR_CODEX_HOME_ENV, &root, true)?;
    let runtime_parent =
        checked_package_environment_path(PACKAGE_SUPERVISOR_RUNTIME_ENV, &root, true)?;
    let report_root = checked_package_environment_path(PACKAGE_SUPERVISOR_REPORT_ENV, &root, true)?;
    write_private_new(&report_root.join("guardian.root"), b"validated\n")?;
    let working_directory = checked_package_subdirectory(&root, "workspace")?;
    let foreground = std::env::var(PACKAGE_SUPERVISOR_FOREGROUND_ENV)?
        .parse::<i32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or("package guardian foreground group was invalid")?;
    let executable = package_provider_executable(provider_target, &root)?;
    write_private_new(&report_root.join("guardian.binary"), b"validated\n")?;
    let profile_id = std::env::var(PACKAGE_SUPERVISOR_PROFILE_ENV)?;
    if Uuid::parse_str(&profile_id)?.to_string() != profile_id {
        return Err("package guardian profile ID was invalid".into());
    }
    write_private_new(&report_root.join("guardian.profile-id"), b"validated\n")?;
    let registry = Registry::at(root.join("supervisor-registry"));
    let profile = registry.find_by_id(Provider::Codex, &profile_id)?;
    if fs::canonicalize(registry.profile_home(&profile)?)? != codex_home {
        return Err("package guardian selected profile home changed".into());
    }
    write_private_new(&report_root.join("guardian.profile"), b"validated\n")?;
    write_private_new(&report_root.join("guardian.entered"), b"entered\n")?;
    arm_packaged_session_observation(report_root.clone())?;
    write_private_new(&report_root.join("guardian.observer"), b"armed\n")?;
    let fixture_compatibility_stage_parent = match provider_target {
        PackageProviderTarget::Official => None,
        PackageProviderTarget::DeterministicFixture => {
            Some(checked_package_subdirectory(&root, "s")?)
        }
    };
    let outcome = run_production_guardian_with_test_seams(
        ProductionGuardianConfig {
            registry: &registry,
            profile: &profile,
            working_directory: &working_directory,
            thread_id: PACKAGE_SUPERVISOR_THREAD_ID,
            codex_executable: &executable,
            runtime_parent: &runtime_parent,
            expected_foreground_process_group: foreground,
            bounds: package_guardian_bounds(provider_target),
            completion,
        },
        PackagedGuardianSeams {
            after_admission: replace_package_profile_config_after_admission,
            fixed_report_root: &report_root,
            recovery_checkpoint,
            fixture_compatibility_stage_parent: fixture_compatibility_stage_parent.as_deref(),
            startup_terminal_channel_write_retained: startup_fault
                == Some(PackageStartupFault::TerminalChannelWriteRetainedStartupRestore),
        },
    );
    let disposition = match outcome {
        GuardianRunOutcome::Terminal(disposition) => disposition,
        GuardianRunOutcome::Retained(retained) => {
            for marker in retained.packaged_marker_names().into_iter().flatten() {
                record_package_diagnostic_marker(&report_root, marker);
            }
            match retained.await_recovery() {
                GuardianRunOutcome::Terminal(disposition) => disposition,
                GuardianRunOutcome::Retained(retained) => {
                    record_package_diagnostic_marker(&report_root, "guardian-recovery.retained");
                    for marker in retained.packaged_marker_names().into_iter().flatten() {
                        record_package_diagnostic_marker(&report_root, marker);
                    }
                    retained.park()
                }
            }
        }
    };
    let observation =
        take_packaged_session_observation().ok_or("package session observer was not armed")?;
    write_package_session_observation(&report_root, &observation)?;
    apply_package_guardian_terminal_disposition(disposition)
}

fn replace_package_profile_config_after_admission(
    codex_home: &Path,
) -> Result<(), GuardianSetupError> {
    let backend = package_supervisor_backend().map_err(|_| GuardianSetupError::Admission)?;
    replace_package_profile_config(codex_home, backend).map_err(|_| GuardianSetupError::Admission)
}

fn package_guardian_bounds(provider_target: PackageProviderTarget) -> GuardianBounds {
    let startup_timeout = match provider_target {
        PackageProviderTarget::Official => PACKAGE_SUPERVISOR_STARTUP_TIMEOUT,
        PackageProviderTarget::DeterministicFixture => PACKAGE_DETERMINISTIC_SUPERVISOR_TIMEOUT,
    };
    GuardianBounds {
        phase_timeout: startup_timeout,
        poll_interval: Duration::from_millis(20),
        startup_timeout,
        compatibility_timeout: match provider_target {
            PackageProviderTarget::Official => PACKAGE_SUPERVISOR_COMPATIBILITY_TIMEOUT,
            PackageProviderTarget::DeterministicFixture => PACKAGE_DETERMINISTIC_SUPERVISOR_TIMEOUT,
        },
        relay_start_timeout: match provider_target {
            PackageProviderTarget::Official => Duration::from_secs(15),
            PackageProviderTarget::DeterministicFixture => {
                PACKAGE_DETERMINISTIC_RELAY_START_TIMEOUT
            }
        },
        containment_timeout: Duration::from_secs(15),
        tui_grace: Duration::from_secs(2),
        tui_forced: Duration::from_secs(5),
        relay_shutdown_timeout: Duration::from_secs(10),
        monitor_shutdown_timeout: Duration::from_secs(10),
        app_grace: Duration::from_secs(2),
        app_forced: Duration::from_secs(5),
        app_cleanup_timeout: Duration::from_secs(10),
        build_cleanup_timeout: match provider_target {
            PackageProviderTarget::Official => PACKAGE_SUPERVISOR_COMPATIBILITY_TIMEOUT,
            PackageProviderTarget::DeterministicFixture => Duration::from_secs(10),
        },
    }
}

struct PackageScratchView<'a> {
    root: &'a Path,
    workspace: &'a Path,
    environment_home: &'a Path,
}

fn package_supervisor_helper_command_from_view(
    role: &str,
    scratch: &PackageScratchView<'_>,
    executable: &Path,
    backend: std::net::SocketAddr,
    recovery_checkpoint: Option<RecoveryCheckpoint>,
    provider_target: PackageProviderTarget,
    startup_fault: Option<PackageStartupFault>,
) -> Result<Command, Box<dyn Error>> {
    let helper = fs::canonicalize(std::env::current_exe()?)?;
    let (launcher_environment, launcher) =
        super::launcher::packaged_launcher_executable_from_environment()?;
    let launcher = validate_package_launcher_for_target(provider_target, scratch.root, &launcher)?;
    let mut command = Command::new(helper);
    command
        .env_clear()
        .args(["--exact", PACKAGE_SUPERVISOR_HELPER_TEST, "--nocapture"])
        .env(PACKAGE_SUPERVISOR_ROLE_ENV, role)
        .env(PACKAGE_SUPERVISOR_ROOT_ENV, scratch.root)
        .env(PACKAGE_SUPERVISOR_BACKEND_ENV, backend.to_string())
        .env(PACKAGE_BINARY_ENV, executable)
        .env(launcher_environment, launcher)
        .env("HOME", scratch.environment_home)
        .env("XDG_CONFIG_HOME", scratch.environment_home.join("config"))
        .env("XDG_DATA_HOME", scratch.environment_home.join("data"))
        .env("XDG_CACHE_HOME", scratch.environment_home.join("cache"))
        .env("XDG_RUNTIME_DIR", scratch.environment_home.join("run"))
        .env("TMPDIR", scratch.environment_home.join("tmp"))
        .env("TERM", "xterm-256color")
        .env(
            "PATH",
            std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
        )
        .current_dir(scratch.workspace);
    project_package_recovery_checkpoint_environment(&mut command, recovery_checkpoint);
    project_package_provider_target_environment(&mut command, provider_target);
    project_package_startup_fault_environment(&mut command, startup_fault);
    Ok(command)
}

fn write_package_resume_rollout(codex_home: &Path, workspace: &Path) -> Result<(), Box<dyn Error>> {
    let sessions = codex_home.join("sessions");
    let year = sessions.join("2026");
    let month = year.join("07");
    let day = month.join("16");
    for directory in [&sessions, &year, &month, &day] {
        private_directory(directory)?;
    }
    let rollout = day.join(format!(
        "rollout-2026-07-16T00-00-00-{PACKAGE_SUPERVISOR_THREAD_ID}.jsonl"
    ));
    let mut contents = Vec::new();
    for record in [
        json!({
            "timestamp": "2026-07-16T00:00:00.000Z",
            "type": "session_meta",
            "payload": {
                "id": PACKAGE_SUPERVISOR_THREAD_ID,
                "session_id": PACKAGE_SUPERVISOR_THREAD_ID,
                "timestamp": "2026-07-16T00:00:00.000Z",
                "cwd": workspace,
                "originator": "codex",
                "cli_version": "0.144.4",
                "source": "cli",
                "model_provider": PACKAGE_SUPERVISOR_MODEL_PROVIDER,
                "parent_thread_id": null
            }
        }),
        json!({
            "timestamp": "2026-07-16T00:00:00.001Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": PACKAGE_SUPERVISOR_STARTUP_SENTINEL
                }]
            }
        }),
        json!({
            "timestamp": "2026-07-16T00:00:00.002Z",
            "type": "event_msg",
            "payload": {
                "type": "user_message",
                "message": PACKAGE_SUPERVISOR_STARTUP_SENTINEL,
                "kind": "plain"
            }
        }),
    ] {
        serde_json::to_writer(&mut contents, &record)?;
        contents.push(b'\n');
    }
    write_private_new(&rollout, &contents)
}

#[test]
fn package_resume_rollout_and_runtime_config_bind_the_same_loopback_provider()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    write_package_resume_rollout(&scratch.codex_home, &scratch.workspace)?;
    let rollout = scratch.codex_home.join("sessions/2026/07/16").join(format!(
        "rollout-2026-07-16T00-00-00-{PACKAGE_SUPERVISOR_THREAD_ID}.jsonl"
    ));
    let first = read_private_bounded(&rollout, 128 * 1024)?
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or("package rollout omitted session metadata")?
        .to_vec();
    let metadata: Value = serde_json::from_slice(&first)?;
    let config: toml::Value = toml::from_str(&package_usage_config("127.0.0.1:12345".parse()?))?;
    assert_eq!(
        metadata
            .pointer("/payload/model_provider")
            .and_then(Value::as_str),
        config.get("model_provider").and_then(toml::Value::as_str)
    );
    assert_eq!(
        metadata
            .pointer("/payload/model_provider")
            .and_then(Value::as_str),
        Some("calcifer_package_smoke")
    );
    scratch.cleanup()
}

#[test]
fn package_official_configs_disable_out_of_scope_dynamic_features() -> Result<(), Box<dyn Error>> {
    let backend = "127.0.0.1:12345".parse()?;
    let scratch = PackageScratch::create()?;
    write_test_config(&scratch.codex_home, backend)?;
    let direct = String::from_utf8(read_private_bounded(
        &scratch.codex_home.join("config.toml"),
        128 * 1024,
    )?)?;

    for config in [direct, package_usage_config(backend)] {
        let config: toml::Value = toml::from_str(&config)?;
        assert_eq!(
            config
                .get("check_for_update_on_startup")
                .and_then(toml::Value::as_bool),
            Some(false),
            "package config allowed an out-of-scope update request"
        );
        assert_eq!(
            config.get("personality").and_then(toml::Value::as_str),
            Some("pragmatic"),
            "package config allowed the official resume fixture to mutate personality"
        );
        assert_eq!(
            config
                .get("tui")
                .and_then(toml::Value::as_table)
                .and_then(|tui| tui.get("show_tooltips"))
                .and_then(toml::Value::as_bool),
            Some(false),
            "package config allowed a dynamic provider tooltip request"
        );
        assert_eq!(
            config
                .get("analytics")
                .and_then(toml::Value::as_table)
                .and_then(|analytics| analytics.get("enabled"))
                .and_then(toml::Value::as_bool),
            Some(false),
            "package config allowed default analytics egress"
        );
        let otel = config
            .get("otel")
            .and_then(toml::Value::as_table)
            .ok_or("package config omitted its OTEL table")?;
        for exporter in ["exporter", "trace_exporter", "metrics_exporter"] {
            assert_eq!(
                otel.get(exporter).and_then(toml::Value::as_str),
                Some("none"),
                "package config did not disable the {exporter}"
            );
        }
        let features = config
            .get("features")
            .and_then(toml::Value::as_table)
            .ok_or("package config omitted its feature table")?;
        for feature in ["shell_snapshot", "apps", "plugins", "remote_plugin"] {
            assert_eq!(
                features.get(feature).and_then(toml::Value::as_bool),
                Some(false),
                "package config did not disable {feature}"
            );
        }
    }
    scratch.cleanup()
}

#[test]
fn package_network_evidence_rejects_non_loopback_provider_hosts_without_echoing_them()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let evidence = scratch.codex_home.join("logs_2.sqlite-wal");
    write_private_new(&evidence, b"http://127.0.0.1:12345/v1")?;
    verify_package_profile_network_evidence(&scratch.codex_home)?;

    fs::remove_file(&evidence)?;
    let forbidden = [
        &b"wss://chatgpt"[..],
        &b".com/backend-api/codex/responses"[..],
    ]
    .concat();
    write_private_new(&evidence, &forbidden)?;
    let error = require_rejected_test_result(
        verify_package_profile_network_evidence(&scratch.codex_home),
        "non-loopback provider evidence was accepted",
    )?;
    assert_eq!(
        error,
        PackageNetworkHermeticityFailure::EvidenceReferenceChatgpt
    );
    assert!(!error.to_string().contains("chatgpt"));
    fs::remove_file(evidence)?;
    scratch.cleanup()
}

#[test]
fn package_network_external_evidence_reference_identifies_only_a_closed_host_category() {
    assert_eq!(
        classify_external_provider_reference(b"prefix CHATGPT.COM suffix"),
        Some(PackageNetworkHermeticityFailure::EvidenceReferenceChatgpt)
    );
    assert_eq!(
        classify_external_provider_reference(b"prefix AUTH.OPENAI.COM suffix"),
        Some(PackageNetworkHermeticityFailure::EvidenceReferenceAuthOpenai)
    );
    assert_eq!(
        classify_external_provider_reference(b"prefix API.OPENAI.COM suffix"),
        Some(PackageNetworkHermeticityFailure::EvidenceReferenceApiOpenai)
    );
    assert_eq!(
        classify_external_provider_reference(b"http://127.0.0.1:12345/v1"),
        None
    );
}

#[test]
fn package_network_evidence_accepts_owned_sqlite_modes_but_rejects_writable_files()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let evidence = scratch.codex_home.join("state_5.sqlite-wal");
    write_private_new(&evidence, b"http://127.0.0.1:12345/v1")?;

    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o644))?;
    verify_package_profile_network_evidence(&scratch.codex_home)?;

    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o664))?;
    let error = require_rejected_test_result(
        verify_package_profile_network_evidence(&scratch.codex_home),
        "group-writable package network evidence was accepted",
    )?;
    assert_eq!(error, PackageNetworkHermeticityFailure::EvidenceFile);

    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o600))?;
    verify_package_profile_network_evidence(&scratch.codex_home)?;
    scratch.cleanup()
}

#[test]
fn package_network_evidence_scans_owned_mode_0644_without_echoing_a_forbidden_host()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let evidence = scratch.codex_home.join("logs_2.sqlite");
    let forbidden = [&b"WSS://CHATGPT"[..], &b".COM/backend-api"[..]].concat();
    write_private_new(&evidence, &forbidden)?;
    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o644))?;

    let error = require_rejected_test_result(
        verify_package_profile_network_evidence(&scratch.codex_home),
        "a forbidden provider host in mode-0644 evidence was accepted",
    )?;
    assert_eq!(
        error,
        PackageNetworkHermeticityFailure::EvidenceReferenceChatgpt
    );
    assert!(!error.to_string().contains("CHATGPT"));
    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o600))?;
    scratch.cleanup()
}

fn prepare_package_registry_network_evidence(
    scratch: &PackageScratch,
    backend: std::net::SocketAddr,
) -> Result<PathBuf, Box<dyn Error>> {
    let registry = Registry::at(scratch.root.join("supervisor-registry"));
    let pending = registry.begin_codex_registration("official-tui-package")?;
    write_package_registration_auth(&pending.home())?;
    let profile = pending.commit(CodexIdentityAdapter::for_test())?;
    let codex_home = fs::canonicalize(registry.profile_home(&profile)?)?;
    replace_package_profile_config(&codex_home, backend)?;
    write_private_new(
        &codex_home.join("logs_2.sqlite-wal"),
        format!("http://{backend}/v1").as_bytes(),
    )?;
    Ok(codex_home)
}

#[test]
fn package_registry_network_evidence_binds_the_exact_loopback_config() -> Result<(), Box<dyn Error>>
{
    let backend = "127.0.0.1:12345".parse()?;
    let scratch = PackageScratch::create()?;
    let codex_home = prepare_package_registry_network_evidence(&scratch, backend)?;
    verify_package_registry_network_hermeticity(&scratch.root, backend)?;

    fs::remove_file(codex_home.join("config.toml"))?;
    let mut drifted = package_usage_config(backend);
    drifted.push_str("\nunexpected_package_authority = true\n");
    write_private_new(&codex_home.join("config.toml"), drifted.as_bytes())?;
    let error = require_rejected_test_result(
        verify_package_registry_network_hermeticity(&scratch.root, backend),
        "a drifted package provider config was accepted",
    )?;
    assert_eq!(error, PackageNetworkHermeticityFailure::ConfigContract);
    scratch.cleanup()
}

#[test]
fn package_registry_network_evidence_rejects_missing_or_non_loopback_authority()
-> Result<(), Box<dyn Error>> {
    let backend = "127.0.0.1:12345".parse()?;
    let scratch = PackageScratch::create()?;
    prepare_package_registry_network_evidence(&scratch, backend)?;

    for invalid in ["127.0.0.1:0", "192.0.2.1:12345"] {
        let error = require_rejected_test_result(
            verify_package_registry_network_hermeticity(&scratch.root, invalid.parse()?),
            "invalid package network authority was accepted",
        )?;
        assert_eq!(error, PackageNetworkHermeticityFailure::Authority);
    }
    scratch.cleanup()
}

#[test]
fn package_network_gate_runs_only_for_a_started_official_generation() -> Result<(), Box<dyn Error>>
{
    let scratch = PackageScratch::create()?;
    let backend = "127.0.0.1:12345".parse()?;
    for (generation_started, target, expected_calls) in [
        (false, PackageProviderTarget::Official, 0),
        (false, PackageProviderTarget::DeterministicFixture, 0),
        (true, PackageProviderTarget::DeterministicFixture, 0),
        (true, PackageProviderTarget::Official, 1),
    ] {
        let mut calls = 0_u8;
        run_package_network_hermeticity_gate(
            generation_started,
            target,
            Some(&scratch.root),
            Some(backend),
            |root, observed_backend| {
                calls = calls.saturating_add(1);
                assert_eq!(root, scratch.root);
                assert_eq!(observed_backend, backend);
                Ok(())
            },
        )?;
        assert_eq!(calls, expected_calls);
    }
    scratch.cleanup()
}

#[test]
fn package_network_gate_fails_closed_only_when_started_official_authority_is_missing()
-> Result<(), Box<dyn Error>> {
    let backend = "127.0.0.1:12345".parse()?;
    for (root, address) in [(None, Some(backend)), (Some(Path::new("/tmp")), None)] {
        assert_eq!(
            run_package_network_hermeticity_gate(
                true,
                PackageProviderTarget::Official,
                root,
                address,
                |_, _| Ok(()),
            ),
            Err(PackageNetworkHermeticityFailure::Authority)
        );
    }
    assert!(
        run_package_network_hermeticity_gate(
            false,
            PackageProviderTarget::Official,
            None,
            None,
            |_, _| Err(PackageNetworkHermeticityFailure::ConfigContract),
        )
        .is_ok()
    );
    assert!(
        run_package_network_hermeticity_gate(
            true,
            PackageProviderTarget::DeterministicFixture,
            None,
            None,
            |_, _| Err(PackageNetworkHermeticityFailure::ConfigContract),
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn package_network_gate_preserves_only_a_closed_verifier_subtype() -> Result<(), Box<dyn Error>> {
    let backend = "127.0.0.1:12345".parse()?;
    let failure = require_rejected_test_result(
        run_package_network_hermeticity_gate(
            true,
            PackageProviderTarget::Official,
            Some(Path::new("/tmp")),
            Some(backend),
            |_, _| Err(PackageNetworkHermeticityFailure::EvidenceReferenceChatgpt),
        ),
        "a failed package network verifier was accepted",
    )?;

    assert_eq!(
        failure,
        PackageNetworkHermeticityFailure::EvidenceReferenceChatgpt
    );
    assert_eq!(
        failure.marker(),
        "package-network.evidence-reference.chatgpt"
    );
    assert_eq!(
        failure.to_string(),
        "the package network hermeticity proof failed"
    );
    assert!(!failure.to_string().contains("provider"));
    Ok(())
}

#[test]
fn package_network_failures_are_closed_fixed_and_payload_free() {
    let failures = [
        PackageNetworkHermeticityFailure::Authority,
        PackageNetworkHermeticityFailure::RegistryRead,
        PackageNetworkHermeticityFailure::RegistryShape,
        PackageNetworkHermeticityFailure::ProfileIdentity,
        PackageNetworkHermeticityFailure::ProfileTarget,
        PackageNetworkHermeticityFailure::ProfileHome,
        PackageNetworkHermeticityFailure::ConfigRead,
        PackageNetworkHermeticityFailure::ConfigContract,
        PackageNetworkHermeticityFailure::EvidenceRoot,
        PackageNetworkHermeticityFailure::EvidenceEntry,
        PackageNetworkHermeticityFailure::EvidenceFile,
        PackageNetworkHermeticityFailure::EvidenceBound,
        PackageNetworkHermeticityFailure::EvidenceReferenceChatgpt,
        PackageNetworkHermeticityFailure::EvidenceReferenceAuthOpenai,
        PackageNetworkHermeticityFailure::EvidenceReferenceApiOpenai,
        PackageNetworkHermeticityFailure::EvidenceMissing,
    ];
    assert_eq!(
        failures.map(PackageNetworkHermeticityFailure::marker),
        PACKAGE_NETWORK_FAILURE_MARKERS
    );
    let markers: BTreeSet<_> = failures
        .iter()
        .copied()
        .map(PackageNetworkHermeticityFailure::marker)
        .collect();
    assert_eq!(markers.len(), failures.len());
    assert!(markers.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("package-network.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
    assert!(
        failures
            .iter()
            .all(|failure| failure.to_string() == "the package network hermeticity proof failed")
    );
}

#[test]
fn package_failure_report_scanner_bridges_only_the_closed_network_catalog()
-> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let report = scratch.root.join("supervisor-report");
    private_directory(&report)?;
    let terminal_marker = PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS[0];
    write_private_new(&report.join(terminal_marker), b"classified\n")?;

    for &marker in PACKAGE_NETWORK_FAILURE_MARKERS {
        let path = report.join(marker);
        write_private_new(&path, b"classified\n")?;
        assert_eq!(
            OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
            Some(marker),
            "a network proof failure must outrank later terminal cleanup"
        );
        fs::remove_file(path)?;
    }
    fs::remove_file(report.join(terminal_marker))?;
    write_private_new(
        &report.join("package-network.user-controlled"),
        b"classified\n",
    )?;
    assert_eq!(
        OfficialTuiPackageHarness::latest_fixed_failure_detail_from_report(&report),
        None,
        "the scanner must reject an unknown network marker"
    );
    scratch.cleanup()
}

fn verify_package_profile_network_evidence(
    codex_home: &Path,
) -> Result<(), PackageNetworkHermeticityFailure> {
    const MAX_EVIDENCE_FILE_BYTES: usize = 16 * 1024 * 1024;
    const MAX_EVIDENCE_TOTAL_BYTES: usize = 64 * 1024 * 1024;
    let metadata = fs::symlink_metadata(codex_home)
        .map_err(|_| PackageNetworkHermeticityFailure::EvidenceRoot)?;
    if fs::canonicalize(codex_home).map_err(|_| PackageNetworkHermeticityFailure::EvidenceRoot)?
        != codex_home
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(PackageNetworkHermeticityFailure::EvidenceRoot);
    }
    let mut evidence_files = 0_usize;
    let mut total_bytes = 0_usize;
    let entries =
        fs::read_dir(codex_home).map_err(|_| PackageNetworkHermeticityFailure::EvidenceEntry)?;
    for entry in entries {
        let entry = entry.map_err(|_| PackageNetworkHermeticityFailure::EvidenceEntry)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(PackageNetworkHermeticityFailure::EvidenceEntry)?;
        let database = name.starts_with("logs_") || name.starts_with("state_");
        let durable = name.ends_with(".sqlite")
            || name.ends_with(".sqlite-wal")
            || name.ends_with(".sqlite-journal");
        if !database || !durable {
            continue;
        }
        let bytes = read_owned_evidence_bounded(&entry.path(), MAX_EVIDENCE_FILE_BYTES)
            .map_err(|_| PackageNetworkHermeticityFailure::EvidenceFile)?;
        evidence_files = evidence_files
            .checked_add(1)
            .ok_or(PackageNetworkHermeticityFailure::EvidenceBound)?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_EVIDENCE_TOTAL_BYTES)
            .ok_or(PackageNetworkHermeticityFailure::EvidenceBound)?;
        // This is a bounded, redacted drift canary, not proof that a socket was
        // opened: SQLite pages can retain pre-connect logs and stale text. The
        // Linux network namespace is the authoritative egress boundary.
        if let Some(failure) = classify_external_provider_reference(&bytes) {
            return Err(failure);
        }
    }
    if evidence_files == 0 {
        return Err(PackageNetworkHermeticityFailure::EvidenceMissing);
    }
    Ok(())
}

fn classify_external_provider_reference(bytes: &[u8]) -> Option<PackageNetworkHermeticityFailure> {
    [
        (
            &b"chatgpt.com"[..],
            PackageNetworkHermeticityFailure::EvidenceReferenceChatgpt,
        ),
        (
            &b"auth.openai.com"[..],
            PackageNetworkHermeticityFailure::EvidenceReferenceAuthOpenai,
        ),
        (
            &b"api.openai.com"[..],
            PackageNetworkHermeticityFailure::EvidenceReferenceApiOpenai,
        ),
    ]
    .into_iter()
    .find_map(|(host, failure)| contains_ascii_case_insensitive(bytes, host).then_some(failure))
}

fn verify_package_registry_network_hermeticity(
    root: &Path,
    expected_backend: std::net::SocketAddr,
) -> Result<(), PackageNetworkHermeticityFailure> {
    if !expected_backend.ip().is_loopback() || expected_backend.port() == 0 {
        return Err(PackageNetworkHermeticityFailure::Authority);
    }
    let registry = root.join("supervisor-registry");
    let profiles_bytes = read_private_bounded(&registry.join("profiles.json"), 128 * 1024)
        .map_err(|_| PackageNetworkHermeticityFailure::RegistryRead)?;
    let value: Value = serde_json::from_slice(&profiles_bytes)
        .map_err(|_| PackageNetworkHermeticityFailure::RegistryRead)?;
    let profiles = value
        .get("profiles")
        .and_then(Value::as_array)
        .filter(|profiles| profiles.len() == 1)
        .ok_or(PackageNetworkHermeticityFailure::RegistryShape)?;
    let profile = profiles
        .first()
        .and_then(Value::as_object)
        .ok_or(PackageNetworkHermeticityFailure::RegistryShape)?;
    let id = profile
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == *id))
        .ok_or(PackageNetworkHermeticityFailure::ProfileIdentity)?;
    if profile.get("provider").and_then(Value::as_str) != Some("codex")
        || profile.get("alias").and_then(Value::as_str) != Some("official-tui-package")
    {
        return Err(PackageNetworkHermeticityFailure::ProfileTarget);
    }
    let codex_home = registry
        .join("profiles")
        .join("codex")
        .join(id)
        .join("home");
    if fs::canonicalize(&codex_home).map_err(|_| PackageNetworkHermeticityFailure::ProfileHome)?
        != codex_home
    {
        return Err(PackageNetworkHermeticityFailure::ProfileHome);
    }
    let config_bytes = read_private_bounded(&codex_home.join("config.toml"), 128 * 1024)
        .map_err(|_| PackageNetworkHermeticityFailure::ConfigRead)?;
    let config = std::str::from_utf8(&config_bytes)
        .ok()
        .and_then(|config| toml::from_str::<toml::Value>(config).ok());
    let expected = toml::from_str::<toml::Value>(&package_usage_config(expected_backend))
        .map_err(|_| PackageNetworkHermeticityFailure::ConfigContract)?;
    if config.as_ref() != Some(&expected) {
        return Err(PackageNetworkHermeticityFailure::ConfigContract);
    }
    verify_package_profile_network_evidence(&codex_home)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageNetworkHermeticityFailure {
    Authority,
    RegistryRead,
    RegistryShape,
    ProfileIdentity,
    ProfileTarget,
    ProfileHome,
    ConfigRead,
    ConfigContract,
    EvidenceRoot,
    EvidenceEntry,
    EvidenceFile,
    EvidenceBound,
    EvidenceReferenceChatgpt,
    EvidenceReferenceAuthOpenai,
    EvidenceReferenceApiOpenai,
    EvidenceMissing,
}

impl PackageNetworkHermeticityFailure {
    const fn marker(self) -> &'static str {
        match self {
            Self::Authority => "package-network.authority",
            Self::RegistryRead => "package-network.registry-read",
            Self::RegistryShape => "package-network.registry-shape",
            Self::ProfileIdentity => "package-network.profile-identity",
            Self::ProfileTarget => "package-network.profile-target",
            Self::ProfileHome => "package-network.profile-home",
            Self::ConfigRead => "package-network.config-read",
            Self::ConfigContract => "package-network.config-contract",
            Self::EvidenceRoot => "package-network.evidence-root",
            Self::EvidenceEntry => "package-network.evidence-entry",
            Self::EvidenceFile => "package-network.evidence-file",
            Self::EvidenceBound => "package-network.evidence-bound",
            Self::EvidenceReferenceChatgpt => "package-network.evidence-reference.chatgpt",
            Self::EvidenceReferenceAuthOpenai => "package-network.evidence-reference.auth-openai",
            Self::EvidenceReferenceApiOpenai => "package-network.evidence-reference.api-openai",
            Self::EvidenceMissing => "package-network.evidence-missing",
        }
    }
}

impl fmt::Display for PackageNetworkHermeticityFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package network hermeticity proof failed")
    }
}

impl Error for PackageNetworkHermeticityFailure {}

fn run_package_network_hermeticity_gate<Verifier>(
    generation_started: bool,
    target: PackageProviderTarget,
    root: Option<&Path>,
    backend: Option<std::net::SocketAddr>,
    verifier: Verifier,
) -> Result<(), PackageNetworkHermeticityFailure>
where
    Verifier: FnOnce(&Path, std::net::SocketAddr) -> Result<(), PackageNetworkHermeticityFailure>,
{
    if !generation_started || target != PackageProviderTarget::Official {
        return Ok(());
    }
    let (Some(root), Some(backend)) = (root, backend) else {
        return Err(PackageNetworkHermeticityFailure::Authority);
    };
    verifier(root, backend)
}

fn package_supervisor_root() -> Result<PathBuf, Box<dyn Error>> {
    let root = std::env::var_os(PACKAGE_SUPERVISOR_ROOT_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("package supervisor root was missing or relative")?;
    if fs::canonicalize(&root)? != root {
        return Err("package supervisor root was not canonical".into());
    }
    let metadata = fs::symlink_metadata(&root)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || read_private_bounded(&root.join("owner.marker"), 64)? != b"calcifer-package-smoke-v1\n"
    {
        return Err("package supervisor root identity was invalid".into());
    }
    Ok(root)
}

fn checked_package_subdirectory(root: &Path, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let expected = root.join(name);
    let canonical = fs::canonicalize(&expected)?;
    if canonical != expected || canonical.parent() != Some(root) {
        return Err("package supervisor subdirectory escaped its private root".into());
    }
    let metadata = fs::symlink_metadata(&canonical)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("package supervisor subdirectory identity was invalid".into());
    }
    Ok(canonical)
}

fn checked_package_environment_path(
    name: &str,
    root: &Path,
    directory: bool,
) -> Result<PathBuf, Box<dyn Error>> {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("package supervisor path was missing or relative")?;
    let canonical = fs::canonicalize(&path)?;
    if canonical != path || !canonical.starts_with(root) || canonical == root {
        return Err("package supervisor path escaped its private root".into());
    }
    let metadata = fs::symlink_metadata(&canonical)?;
    if directory
        && (!metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700)
    {
        return Err("package supervisor directory identity was invalid".into());
    }
    Ok(canonical)
}

fn package_supervisor_backend() -> Result<std::net::SocketAddr, Box<dyn Error>> {
    let address = std::env::var(PACKAGE_SUPERVISOR_BACKEND_ENV)?.parse::<std::net::SocketAddr>()?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("package supervisor backend was not loopback-only".into());
    }
    Ok(address)
}

/// Constant-space matcher for the fixed package-only startup sequence. It
/// retains only a static pattern reference, the current prefix length, and a
/// sticky observation bit; no terminal bytes cross the reader thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageFixedOutputMatcher {
    pattern: &'static [u8],
    matched_prefix: usize,
    seen: bool,
}

impl PackageFixedOutputMatcher {
    const fn new(pattern: &'static [u8]) -> Self {
        Self {
            pattern,
            matched_prefix: 0,
            seen: false,
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        if self.seen || self.pattern.is_empty() {
            return;
        }
        for &byte in bytes {
            self.observe_byte(byte);
            if self.matched_prefix == self.pattern.len() {
                return;
            }
        }
    }

    fn observe_byte(&mut self, byte: u8) {
        if self.seen || self.pattern.is_empty() {
            return;
        }
        self.matched_prefix =
            advance_package_fixed_output_match(self.pattern, self.matched_prefix, byte);
        self.seen = self.matched_prefix == self.pattern.len();
    }

    const fn seen(self) -> bool {
        self.seen
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PackageHandoffProbePhase {
    VersionGatePassed,
    SchemaGatePassed,
    ForkAppServerSpawned,
    InitializeRequestSent,
    InitializeResponseReceived,
    ForkRequestSent,
    ForkResponseReceived,
    ForkResponseValidated,
    ForkAppServerShutdown,
    FingerprintsStable,
    ForkGatePassed,
    RemoteAppServerReady,
    ReadinessProxyReady,
    RemoteTuiSpawned,
    RemoteTuiReadResumeReady,
    ReadinessProxyShutdown,
    RemoteAppServerShutdown,
}

impl PackageHandoffProbePhase {
    const fn fixed_label(self) -> &'static str {
        match self {
            Self::VersionGatePassed => "handoff.version-gate-passed",
            Self::SchemaGatePassed => "handoff.schema-gate-passed",
            Self::ForkAppServerSpawned => "handoff.fork-app-server-spawned",
            Self::InitializeRequestSent => "handoff.initialize-request-sent",
            Self::InitializeResponseReceived => "handoff.initialize-response-received",
            Self::ForkRequestSent => "handoff.fork-request-sent",
            Self::ForkResponseReceived => "handoff.fork-response-received",
            Self::ForkResponseValidated => "handoff.fork-response-validated",
            Self::ForkAppServerShutdown => "handoff.fork-app-server-shutdown",
            Self::FingerprintsStable => "handoff.fingerprints-stable",
            Self::ForkGatePassed => "handoff.fork-gate-passed",
            Self::RemoteAppServerReady => "handoff.remote-app-server-ready",
            Self::ReadinessProxyReady => "handoff.readiness-proxy-ready",
            Self::RemoteTuiSpawned => "handoff.remote-tui-spawned",
            Self::RemoteTuiReadResumeReady => "handoff.remote-tui-read-resume-ready",
            Self::ReadinessProxyShutdown => "handoff.readiness-proxy-shutdown",
            Self::RemoteAppServerShutdown => "handoff.remote-app-server-shutdown",
        }
    }
}

const PACKAGE_HANDOFF_PROBE_PHASES: [(PackageHandoffProbePhase, &[u8]); 17] = [
    (
        PackageHandoffProbePhase::VersionGatePassed,
        b"handoff probe: version gate passed",
    ),
    (
        PackageHandoffProbePhase::SchemaGatePassed,
        b"handoff probe: schema gate passed",
    ),
    (
        PackageHandoffProbePhase::ForkAppServerSpawned,
        b"handoff probe: fork app-server spawned",
    ),
    (
        PackageHandoffProbePhase::InitializeRequestSent,
        b"handoff probe: initialize request sent",
    ),
    (
        PackageHandoffProbePhase::InitializeResponseReceived,
        b"handoff probe: initialize response received",
    ),
    (
        PackageHandoffProbePhase::ForkRequestSent,
        b"handoff probe: fork request sent",
    ),
    (
        PackageHandoffProbePhase::ForkResponseReceived,
        b"handoff probe: fork response received",
    ),
    (
        PackageHandoffProbePhase::ForkResponseValidated,
        b"handoff probe: fork response validation passed",
    ),
    (
        PackageHandoffProbePhase::ForkAppServerShutdown,
        b"handoff probe: fork app-server shut down",
    ),
    (
        PackageHandoffProbePhase::FingerprintsStable,
        b"handoff probe: source and target fingerprints remained stable",
    ),
    (
        PackageHandoffProbePhase::ForkGatePassed,
        b"handoff probe: fork gate passed",
    ),
    (
        PackageHandoffProbePhase::RemoteAppServerReady,
        b"handoff probe: remote app-server socket ready",
    ),
    (
        PackageHandoffProbePhase::ReadinessProxyReady,
        b"handoff probe: readiness proxy ready",
    ),
    (
        PackageHandoffProbePhase::RemoteTuiSpawned,
        b"handoff probe: remote TUI spawned",
    ),
    (
        PackageHandoffProbePhase::RemoteTuiReadResumeReady,
        b"handoff probe: remote TUI read/resume ready",
    ),
    (
        PackageHandoffProbePhase::ReadinessProxyShutdown,
        b"handoff probe: readiness proxy shut down while connected",
    ),
    (
        PackageHandoffProbePhase::RemoteAppServerShutdown,
        b"handoff probe: remote app-server shut down",
    ),
];

/// Constant-space, allowlist-only progress extraction for the compatibility
/// subprocess. Only the next expected fixed marker is eligible, so an
/// out-of-order marker cannot become progress if its predecessors appear
/// later. It retains one matcher prefix and a closed phase enum, never terminal
/// bytes or provider payloads.
struct PackageHandoffProbeProgress {
    next_index: usize,
    next_matcher: Option<PackageFixedOutputMatcher>,
    latest: Option<PackageHandoffProbePhase>,
}

impl PackageHandoffProbeProgress {
    fn new() -> Self {
        Self {
            next_index: 0,
            next_matcher: Some(PackageFixedOutputMatcher::new(
                PACKAGE_HANDOFF_PROBE_PHASES[0].1,
            )),
            latest: None,
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            let Some(matcher) = self.next_matcher.as_mut() else {
                return;
            };
            matcher.observe_byte(byte);
            if !matcher.seen() {
                continue;
            }
            self.latest = Some(PACKAGE_HANDOFF_PROBE_PHASES[self.next_index].0);
            self.next_index += 1;
            self.next_matcher = PACKAGE_HANDOFF_PROBE_PHASES
                .get(self.next_index)
                .map(|(_, marker)| PackageFixedOutputMatcher::new(marker));
        }
    }

    const fn latest(&self) -> Option<PackageHandoffProbePhase> {
        self.latest
    }
}

fn advance_package_fixed_output_match(pattern: &[u8], matched_prefix: usize, byte: u8) -> usize {
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

fn drain_package_pty_output(
    mut descriptor: File,
    cancellation: Receiver<()>,
    startup_sentinel_observed: SyncSender<()>,
    response_sentinel_observed: SyncSender<()>,
) -> Result<PackageOutputDrain, String> {
    let mut total = 0_usize;
    let mut startup_matcher =
        PackageFixedOutputMatcher::new(PACKAGE_SUPERVISOR_STARTUP_SENTINEL.as_bytes());
    let mut response_matcher = PackagedTuiOutputMatcher::new();
    let mut handoff_probe_progress = PackageHandoffProbeProgress::new();
    let mut startup_sentinel_observed = Some(startup_sentinel_observed);
    let mut response_sentinel_observed = Some(response_sentinel_observed);
    let mut buffer = [0_u8; 8192];
    loop {
        match cancellation.try_recv() {
            Ok(()) => {
                return Ok(PackageOutputDrain {
                    total_bytes: total,
                    response_sentinel_seen: response_matcher.seen(),
                    eof: false,
                    handoff_probe_phase: handoff_probe_progress.latest(),
                });
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("package PTY output cancellation authority disappeared".to_owned());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        match descriptor.read(&mut buffer) {
            Ok(0) => {
                return Ok(PackageOutputDrain {
                    total_bytes: total,
                    response_sentinel_seen: response_matcher.seen(),
                    eof: true,
                    handoff_probe_phase: handoff_probe_progress.latest(),
                });
            }
            Ok(count) => {
                total = total
                    .checked_add(count)
                    .ok_or_else(|| "package PTY output count overflowed".to_owned())?;
                if total > PACKAGE_SUPERVISOR_OUTPUT_LIMIT {
                    return Err("package PTY output exceeded its fixed bound".to_owned());
                }
                startup_matcher.observe(&buffer[..count]);
                handoff_probe_progress.observe(&buffer[..count]);
                if startup_matcher.seen() {
                    if let Some(startup_sentinel_observed) = startup_sentinel_observed.take() {
                        startup_sentinel_observed.try_send(()).map_err(|_| {
                            "package TUI startup observation channel disappeared".to_owned()
                        })?;
                    }
                }
                response_matcher.observe(&buffer[..count]);
                if response_matcher.seen() {
                    if let Some(response_sentinel_observed) = response_sentinel_observed.take() {
                        response_sentinel_observed.try_send(()).map_err(|_| {
                            "package TUI response observation channel disappeared".to_owned()
                        })?;
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            // Both Linux and Darwin report EIO after the final PTY slave
            // closes. Treat that kernel terminal condition as exact EOF.
            Err(error) if error.raw_os_error() == Some(5) => {
                return Ok(PackageOutputDrain {
                    total_bytes: total,
                    response_sentinel_seen: response_matcher.seen(),
                    eof: true,
                    handoff_probe_phase: handoff_probe_progress.latest(),
                });
            }
            Err(_) => return Err("package PTY output read failed".to_owned()),
        }
    }
}

#[test]
fn package_fixed_output_matcher_detects_startup_history_across_chunks_without_retaining_output() {
    let mut matcher =
        PackageFixedOutputMatcher::new(PACKAGE_SUPERVISOR_STARTUP_SENTINEL.as_bytes());
    matcher.observe(b"unrelated calcifer package startup ");
    assert!(!matcher.seen());
    matcher.observe(b"history sentinel suffix");
    assert!(matcher.seen());
    matcher.observe(b"arbitrary later terminal output");
    assert!(matcher.seen());
}

#[test]
fn package_handoff_probe_progress_requires_a_contiguous_allowlisted_phase_prefix() {
    let mut progress = PackageHandoffProbeProgress::new();
    progress.observe(b"private terminal output and credentials");
    assert_eq!(progress.latest(), None);

    progress.observe(PACKAGE_HANDOFF_PROBE_PHASES[7].1);
    progress.observe(PACKAGE_HANDOFF_PROBE_PHASES[16].1);
    assert_eq!(
        progress.latest(),
        None,
        "isolated later markers must not manufacture skipped progress"
    );

    for (expected, marker) in PACKAGE_HANDOFF_PROBE_PHASES[..6].iter().copied() {
        progress.observe(marker);
        progress.observe(b"\n");
        assert_eq!(progress.latest(), Some(expected));
    }
    progress.observe(PACKAGE_HANDOFF_PROBE_PHASES[6].1);
    assert_eq!(
        progress.latest(),
        Some(PackageHandoffProbePhase::ForkResponseReceived),
        "an out-of-order marker must be observed again after its predecessor"
    );
    progress.observe(PACKAGE_HANDOFF_PROBE_PHASES[7].1);
    assert_eq!(
        progress.latest(),
        Some(PackageHandoffProbePhase::ForkResponseValidated)
    );

    progress.observe(b"handoff probe: TUI output bytes=private overflow=false failed=false");
    assert_eq!(
        progress.latest(),
        Some(PackageHandoffProbePhase::ForkResponseValidated),
        "dynamic diagnostic text must not become structured progress"
    );

    progress.observe(PACKAGE_HANDOFF_PROBE_PHASES[8].1);
    assert_eq!(
        progress.latest(),
        Some(PackageHandoffProbePhase::ForkAppServerShutdown)
    );
}

#[test]
fn package_pty_output_drain_publishes_distinct_startup_and_response_observations_once()
-> Result<(), Box<dyn Error>> {
    let (reader, mut writer) = UnixStream::pair()?;
    writer.write_all(b"prefix ")?;
    writer.write_all(PACKAGE_SUPERVISOR_STARTUP_SENTINEL.as_bytes())?;
    writer.write_all(PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes())?;
    writer.write_all(PACKAGE_SUPERVISOR_STARTUP_SENTINEL.as_bytes())?;
    writer.write_all(PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes())?;
    for (_, marker) in &PACKAGE_HANDOFF_PROBE_PHASES[..8] {
        writer.write_all(marker)?;
        writer.write_all(b"\n")?;
    }
    drop(writer);

    let descriptor = rustix::io::fcntl_dupfd_cloexec(reader.as_fd(), 3)?;
    let (_cancel, cancellation) = mpsc::sync_channel(1);
    let (startup_sender, startup_observed) = mpsc::sync_channel(1);
    let (response_sender, response_observed) = mpsc::sync_channel(1);
    let drain = drain_package_pty_output(
        File::from(descriptor),
        cancellation,
        startup_sender,
        response_sender,
    )?;

    assert!(drain.response_sentinel_seen);
    assert_eq!(
        drain.handoff_probe_phase,
        Some(PackageHandoffProbePhase::ForkResponseValidated)
    );
    assert_eq!(startup_observed.recv_timeout(IO_TIMEOUT), Ok(()));
    assert_eq!(
        startup_observed.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    );
    assert_eq!(response_observed.recv_timeout(IO_TIMEOUT), Ok(()));
    assert_eq!(
        response_observed.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    );
    Ok(())
}

#[test]
fn package_pty_output_drain_does_not_treat_startup_history_as_current_response()
-> Result<(), Box<dyn Error>> {
    let (reader, mut writer) = UnixStream::pair()?;
    writer.write_all(PACKAGE_SUPERVISOR_STARTUP_SENTINEL.as_bytes())?;
    drop(writer);

    let descriptor = rustix::io::fcntl_dupfd_cloexec(reader.as_fd(), 3)?;
    let (_cancel, cancellation) = mpsc::sync_channel(1);
    let (startup_sender, startup_observed) = mpsc::sync_channel(1);
    let (response_sender, response_observed) = mpsc::sync_channel(1);
    let drain = drain_package_pty_output(
        File::from(descriptor),
        cancellation,
        startup_sender,
        response_sender,
    )?;

    assert!(!drain.response_sentinel_seen);
    assert_eq!(startup_observed.recv_timeout(IO_TIMEOUT), Ok(()));
    assert_eq!(
        startup_observed.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    );
    assert_eq!(
        response_observed.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    );
    Ok(())
}

#[test]
fn package_tui_submissions_require_exact_bracketed_paste_followed_by_enter() {
    assert_eq!(
        decode_package_tui_submission(PACKAGE_SUPERVISOR_INITIAL_INPUT),
        Ok(PACKAGE_SUPERVISOR_INITIAL_PROMPT.as_bytes())
    );
    assert_eq!(
        decode_package_tui_submission(PACKAGE_SUPERVISOR_EXIT_INPUT),
        Ok(b"/quit".as_slice())
    );

    for malformed in [
        b"calcifer-initial-gate-sentinel\r".as_slice(),
        b"\x1b[200~calcifer-initial-gate-sentinel\x1b[201~".as_slice(),
        b"\x1b[200~\x1b[201~\r".as_slice(),
        b"\x1b[200~private\rtext\x1b[201~\r".as_slice(),
        b"\x1b[200~private\x1b[201~trailing\r".as_slice(),
    ] {
        assert!(decode_package_tui_submission(malformed).is_err());
    }
}

#[test]
fn package_input_transcript_accepts_only_ordered_exact_wire_bytes() {
    let expected = [
        PACKAGE_SUPERVISOR_INITIAL_INPUT,
        PACKAGE_SUPERVISOR_EXIT_INPUT,
    ]
    .concat();

    for length in 0..expected.len() {
        assert_eq!(
            classify_package_input_transcript(&expected[..length], &expected),
            PackageInputTranscriptProgress::Pending
        );
    }
    assert_eq!(
        classify_package_input_transcript(&expected, &expected),
        PackageInputTranscriptProgress::Exact
    );
    for diverged in [
        b"calcifer-initial-gate-sentinel\r".as_slice(),
        PACKAGE_SUPERVISOR_EXIT_INPUT,
        [
            PACKAGE_SUPERVISOR_INITIAL_INPUT,
            PACKAGE_SUPERVISOR_INITIAL_INPUT,
        ]
        .concat()
        .as_slice(),
        [expected.as_slice(), b"unexpected"].concat().as_slice(),
    ] {
        assert_eq!(
            classify_package_input_transcript(diverged, &expected),
            PackageInputTranscriptProgress::Diverged
        );
    }
}

#[test]
fn package_live_input_transcript_retries_only_a_concurrent_snapshot_change()
-> Result<(), Box<dyn Error>> {
    let expected = PACKAGE_SUPERVISOR_EXIT_INPUT;
    let mut reads = VecDeque::from([
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "live transcript changed while read",
        )),
        Ok(expected.to_vec()),
    ]);
    wait_for_package_input_transcript_with_reader(
        expected,
        Instant::now() + Duration::from_secs(1),
        || {
            reads
                .pop_front()
                .ok_or_else(|| std::io::Error::other("test read sequence was exhausted"))?
        },
    )?;
    assert!(reads.is_empty());

    let mut unsafe_reads = 0_u8;
    let error = require_rejected_test_result(
        wait_for_package_input_transcript_with_reader(
            expected,
            Instant::now() + Duration::from_secs(1),
            || {
                unsafe_reads = unsafe_reads.saturating_add(1);
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "private identity changed",
                ))
            },
        ),
        "an unsafe live transcript identity was retried or accepted",
    )?;
    assert_eq!(unsafe_reads, 1);
    assert_eq!(error.to_string(), "private identity changed");
    Ok(())
}

#[test]
fn package_private_read_retries_only_same_inode_append_progress() -> Result<(), Box<dyn Error>> {
    let scratch = PackageScratch::create()?;
    let path = scratch.root.join("live-read-classification");
    write_private_new(&path, b"before")?;
    let before = fs::metadata(&path)?;
    OpenOptions::new()
        .append(true)
        .open(&path)?
        .write_all(b"-after")?;
    let after = fs::metadata(&path)?;

    let progress = require_rejected_test_result(
        validate_private_bounded_read_completion(
            &before,
            &after,
            usize::try_from(before.len())?,
            128,
        ),
        "an append racing a private read was not classified as progress",
    )?;
    assert_eq!(progress.kind(), std::io::ErrorKind::WouldBlock);

    for (bytes_read, maximum, context) in [
        (
            usize::try_from(before.len())?.saturating_sub(1),
            128,
            "truncate-then-regrow race",
        ),
        (
            usize::try_from(after.len())?.saturating_add(1),
            128,
            "read beyond final length",
        ),
        (10, 10, "append beyond the configured cap"),
    ] {
        let unsafe_growth = require_rejected_test_result(
            validate_private_bounded_read_completion(&before, &after, bytes_read, maximum),
            "unsafe same-inode growth was accepted as append progress",
        )?;
        assert_eq!(
            unsafe_growth.kind(),
            std::io::ErrorKind::InvalidData,
            "{context} was retried"
        );
    }

    OpenOptions::new().write(true).open(&path)?.set_len(3)?;
    let truncated = fs::metadata(&path)?;
    let truncation = require_rejected_test_result(
        validate_private_bounded_read_completion(&after, &truncated, 3, 128),
        "same-inode truncation was accepted as append progress",
    )?;
    assert_eq!(truncation.kind(), std::io::ErrorKind::InvalidData);

    let rewritten_path = scratch.root.join("same-length-rewrite");
    write_private_new(&rewritten_path, b"before")?;
    let mut rewritten = OpenOptions::new().write(true).open(&rewritten_path)?;
    rewritten.set_times(
        fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1)),
    )?;
    let before_rewrite = rewritten.metadata()?;
    rewritten.write_all(b"rewrit")?;
    rewritten.set_times(
        fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH + Duration::from_secs(2)),
    )?;
    let after_rewrite = rewritten.metadata()?;
    let rewrite = require_rejected_test_result(
        validate_private_bounded_read_completion(
            &before_rewrite,
            &after_rewrite,
            b"rewrit".len(),
            128,
        ),
        "same-length rewrite was accepted as append progress",
    )?;
    assert_eq!(rewrite.kind(), std::io::ErrorKind::InvalidData);

    let oversized = require_rejected_test_result(
        validate_private_bounded_read_completion(&after, &after, 129, 128),
        "an oversized private read was accepted as progress",
    )?;
    assert_eq!(oversized.kind(), std::io::ErrorKind::InvalidData);
    scratch.cleanup()
}

#[test]
fn package_private_read_rejects_restored_mtime_when_change_time_differs()
-> Result<(), Box<dyn Error>> {
    let before = PrivateBoundedReadVersion {
        length: b"before".len(),
        modified: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        change_time: (41, 7),
    };
    let rewritten = PrivateBoundedReadVersion {
        length: before.length,
        modified: before.modified,
        change_time: (41, 8),
    };

    let error = require_rejected_test_result(
        validate_private_bounded_read_version(before, rewritten, before.length, 128),
        "same-length rewrite with restored mtime was accepted as stable",
    )?;
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    Ok(())
}

fn write_package_pty_input(
    master: &PtyMaster,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err("package PTY input fragment was invalid".into());
    }
    let mut written = 0_usize;
    while written < bytes.len() {
        if Instant::now() >= deadline {
            return Err("package PTY input write exceeded its deadline".into());
        }
        match rustix::io::write(master.as_fd(), &bytes[written..]) {
            Ok(0) => return Err("package PTY input write made no progress".into()),
            Ok(count) => written = written.saturating_add(count),
            Err(rustix::io::Errno::INTR) => {}
            Err(rustix::io::Errno::AGAIN) => thread::sleep(Duration::from_millis(1)),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn wait_for_package_raw_mode(master: &PtyMaster, deadline: Instant) -> Result<(), Box<dyn Error>> {
    while Instant::now() < deadline {
        let modes = rustix::termios::tcgetattr(master)?.local_modes;
        if !modes.contains(rustix::termios::LocalModes::ICANON)
            && !modes.contains(rustix::termios::LocalModes::ECHO)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err("package outer PTY did not enter raw mode".into())
}

fn fixed_package_failure_marker_is_valid(report: &Path, marker: &str) -> bool {
    read_private_bounded(&report.join(marker), b"classified\n".len())
        .is_ok_and(|payload| payload == b"classified\n")
}

fn fixed_package_startup_failure_marker(name: &str) -> Option<&'static str> {
    PACKAGED_COMPATIBILITY_FAILURE_MARKERS
        .iter()
        .copied()
        .chain(PACKAGED_APP_SOCKET_FAILURE_MARKERS.iter().copied())
        .chain(PACKAGED_SESSION_STARTUP_FAILURE_MARKERS.iter().copied())
        .chain(PACKAGED_STARTUP_FAILURE_MARKERS.iter().copied())
        .find(|marker| *marker == name)
}

fn fixed_package_startup_failure_from_report(report: &Path) -> Option<FixedPackageStartupFailure> {
    PACKAGED_STARTUP_FAILURE_MARKERS
        .iter()
        .copied()
        .find_map(|generic| {
            if !fixed_package_failure_marker_is_valid(report, generic) {
                return None;
            }
            let detail = match generic {
                "startup-failure.compatibility" => PACKAGED_COMPATIBILITY_FAILURE_MARKERS
                    .iter()
                    .copied()
                    .find(|marker| fixed_package_failure_marker_is_valid(report, marker)),
                "startup-failure.app-socket" => PACKAGED_APP_SOCKET_FAILURE_MARKERS
                    .iter()
                    .copied()
                    .find(|marker| fixed_package_failure_marker_is_valid(report, marker)),
                "startup-failure.session-readiness" => PACKAGED_SESSION_STARTUP_FAILURE_MARKERS
                    .iter()
                    .copied()
                    .find(|marker| fixed_package_failure_marker_is_valid(report, marker)),
                _ => None,
            };
            Some(FixedPackageStartupFailure(detail.unwrap_or(generic)))
        })
}

fn wait_for_private_marker_or_fixed_startup_failure(
    report: &Path,
    path: &Path,
    expected: &[u8],
    deadline: Instant,
) -> Result<PackageInitialGateObservation, Box<dyn Error>> {
    let mut next_failure_scan = Instant::now();
    loop {
        let now = Instant::now();
        if now >= next_failure_scan {
            if let Some(failure) = fixed_package_startup_failure_from_report(report) {
                return Ok(PackageInitialGateObservation::StartupFailure(failure));
            }
            next_failure_scan = now
                .checked_add(PACKAGE_FIXED_FAILURE_POLL_INTERVAL)
                .map(|next| next.min(deadline))
                .unwrap_or(deadline);
        }
        match read_private_bounded(path, expected.len().saturating_add(1)) {
            Ok(bytes) if bytes == expected => return Ok(PackageInitialGateObservation::Opened),
            Ok(_) => return Err("package supervisor marker payload was invalid".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if now >= deadline {
            let name = path
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or("unknown");
            return Err(format!("package supervisor marker `{name}` exceeded its deadline").into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_private_marker(
    path: &Path,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    loop {
        match read_private_bounded(path, expected.len().saturating_add(1)) {
            Ok(bytes) if bytes == expected => return Ok(()),
            Ok(_) => return Err("package supervisor marker payload was invalid".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            let name = path
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or("unknown");
            return Err(format!("package supervisor marker `{name}` exceeded its deadline").into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_private_marker_while_child_live(
    path: &Path,
    expected: &[u8],
    child: PackageChildMarker,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    loop {
        match read_private_bounded(path, expected.len().saturating_add(1)) {
            Ok(bytes) if bytes == expected => return Ok(()),
            Ok(_) => return Err("package supervisor marker payload was invalid".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if observe_process_job_identity(child.pid)?
            .is_none_or(|(process_group, _)| process_group != child.pgid)
        {
            return Err("package guardian exited before the official TUI started".into());
        }
        if Instant::now() >= deadline {
            let name = path
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or("unknown");
            return Err(format!("package supervisor marker `{name}` exceeded its deadline").into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_private_file(
    path: &Path,
    maximum: usize,
    deadline: Instant,
) -> Result<Vec<u8>, Box<dyn Error>> {
    loop {
        match read_private_bounded(path, maximum) {
            Ok(bytes) if !bytes.is_empty() => return Ok(bytes),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err("package supervisor file exceeded its deadline".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageInputTranscriptProgress {
    Pending,
    Exact,
    Diverged,
}

fn classify_package_input_transcript(
    observed: &[u8],
    expected: &[u8],
) -> PackageInputTranscriptProgress {
    if observed == expected {
        PackageInputTranscriptProgress::Exact
    } else if expected.starts_with(observed) {
        PackageInputTranscriptProgress::Pending
    } else {
        PackageInputTranscriptProgress::Diverged
    }
}

fn wait_for_package_input_transcript(
    path: &Path,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    wait_for_package_input_transcript_with_reader(expected, deadline, || {
        read_private_bounded(path, 128 * 1024)
    })
}

fn wait_for_package_input_transcript_with_reader(
    expected: &[u8],
    deadline: Instant,
    mut read: impl FnMut() -> std::io::Result<Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    loop {
        match read() {
            Ok(bytes) => match classify_package_input_transcript(&bytes, expected) {
                PackageInputTranscriptProgress::Exact => return Ok(()),
                PackageInputTranscriptProgress::Diverged => {
                    return Err("package terminal input diverged from the exact transcript".into());
                }
                PackageInputTranscriptProgress::Pending => {}
            },
            // `input.live` is append-only and observed concurrently with the
            // guardian's post-forward commit. A stable descriptor whose
            // length or mtime changed during one bounded read is expected
            // progress, not an identity failure. Unsafe metadata and all
            // other I/O errors remain immediately fatal.
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(error.into());
            }
        }
        if Instant::now() >= deadline {
            return Err("package terminal input observation exceeded its deadline".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    count_bytes(haystack, needle) != 0
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageChildMarker {
    pid: i32,
    pgid: i32,
}

const PACKAGE_OFFICIAL_TUI_GROUP_FAILURE_MARKERS: &[&str] = &[
    "exercise.tui-group-validation-failed.leader",
    "exercise.tui-group-validation-failed.job-identity",
    "exercise.tui-group-validation-failed.empty",
    "exercise.tui-group-validation-failed.snapshot",
    "exercise.tui-group-validation-failed.not-stably-live.no-observation",
    "exercise.tui-group-validation-failed.not-stably-live.mixed",
    "exercise.tui-group-validation-failed.not-stably-live.unstable",
    "exercise.tui-group-validation-failed.not-stably-live.empty",
    "exercise.tui-group-validation-failed.not-stably-live.leader",
    "exercise.tui-group-validation-failed.not-stably-live.duplicate-process",
    "exercise.tui-group-validation-failed.not-stably-live.identity",
    "exercise.tui-group-validation-failed.not-stably-live.live-state",
    "exercise.tui-group-validation-failed.not-stably-live.stopped-state",
    "exercise.tui-group-validation-failed.not-stably-live.missing-stopped-member",
    "exercise.tui-group-validation-failed.descriptor.invalid-argument",
    "exercise.tui-group-validation-failed.descriptor.process-limit",
    "exercise.tui-group-validation-failed.descriptor.member-limit",
    "exercise.tui-group-validation-failed.descriptor.descriptor-limit",
    "exercise.tui-group-validation-failed.descriptor.forbidden-identity-limit",
    "exercise.tui-group-validation-failed.descriptor.deadline",
    "exercise.tui-group-validation-failed.descriptor.permission-denied",
    "exercise.tui-group-validation-failed.descriptor.process-user-mismatch",
    "exercise.tui-group-validation-failed.descriptor.process-changed",
    "exercise.tui-group-validation-failed.descriptor.descriptor-changed",
    "exercise.tui-group-validation-failed.descriptor.forbidden-descriptor",
    "exercise.tui-group-validation-failed.descriptor.unsupported-descriptor",
    "exercise.tui-group-validation-failed.descriptor.observation-failed",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageOfficialTuiGroupFailure {
    Leader,
    JobIdentity,
    Descriptor(calcifer_unix_child_fd::ProcessGroupDescriptorScanError),
    Empty,
    Snapshot,
    NotStablyLiveNoObservation,
    NotStablyLiveMixed,
    NotStablyLive(PackageProcessSnapshotError),
}

impl PackageOfficialTuiGroupFailure {
    const fn marker(self) -> &'static str {
        use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

        match self {
            Self::Leader => "exercise.tui-group-validation-failed.leader",
            Self::JobIdentity => "exercise.tui-group-validation-failed.job-identity",
            Self::Empty => "exercise.tui-group-validation-failed.empty",
            Self::Snapshot => "exercise.tui-group-validation-failed.snapshot",
            Self::NotStablyLiveNoObservation => {
                "exercise.tui-group-validation-failed.not-stably-live.no-observation"
            }
            Self::NotStablyLiveMixed => {
                "exercise.tui-group-validation-failed.not-stably-live.mixed"
            }
            Self::NotStablyLive(PackageProcessSnapshotError::Unstable) => {
                "exercise.tui-group-validation-failed.not-stably-live.unstable"
            }
            Self::NotStablyLive(PackageProcessSnapshotError::Empty) => {
                "exercise.tui-group-validation-failed.not-stably-live.empty"
            }
            Self::NotStablyLive(PackageProcessSnapshotError::Leader) => {
                "exercise.tui-group-validation-failed.not-stably-live.leader"
            }
            Self::NotStablyLive(PackageProcessSnapshotError::DuplicateProcess) => {
                "exercise.tui-group-validation-failed.not-stably-live.duplicate-process"
            }
            Self::NotStablyLive(PackageProcessSnapshotError::Identity) => {
                "exercise.tui-group-validation-failed.not-stably-live.identity"
            }
            Self::NotStablyLive(PackageProcessSnapshotError::LiveState) => {
                "exercise.tui-group-validation-failed.not-stably-live.live-state"
            }
            Self::NotStablyLive(PackageProcessSnapshotError::StoppedState) => {
                "exercise.tui-group-validation-failed.not-stably-live.stopped-state"
            }
            Self::NotStablyLive(PackageProcessSnapshotError::MissingStoppedMember) => {
                "exercise.tui-group-validation-failed.not-stably-live.missing-stopped-member"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::InvalidArgument) => {
                "exercise.tui-group-validation-failed.descriptor.invalid-argument"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::ProcessLimit) => {
                "exercise.tui-group-validation-failed.descriptor.process-limit"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::MemberLimit) => {
                "exercise.tui-group-validation-failed.descriptor.member-limit"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::DescriptorLimit) => {
                "exercise.tui-group-validation-failed.descriptor.descriptor-limit"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::ForbiddenIdentityLimit) => {
                "exercise.tui-group-validation-failed.descriptor.forbidden-identity-limit"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::Deadline) => {
                "exercise.tui-group-validation-failed.descriptor.deadline"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::PermissionDenied) => {
                "exercise.tui-group-validation-failed.descriptor.permission-denied"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::ProcessUserMismatch) => {
                "exercise.tui-group-validation-failed.descriptor.process-user-mismatch"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::ProcessChanged) => {
                "exercise.tui-group-validation-failed.descriptor.process-changed"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::DescriptorChanged) => {
                "exercise.tui-group-validation-failed.descriptor.descriptor-changed"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::ForbiddenDescriptor) => {
                "exercise.tui-group-validation-failed.descriptor.forbidden-descriptor"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::UnsupportedDescriptor) => {
                "exercise.tui-group-validation-failed.descriptor.unsupported-descriptor"
            }
            Self::Descriptor(ProcessGroupDescriptorScanError::ObservationFailed) => {
                "exercise.tui-group-validation-failed.descriptor.observation-failed"
            }
        }
    }
}

impl fmt::Display for PackageOfficialTuiGroupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the official TUI process-group validation failed")
    }
}

impl Error for PackageOfficialTuiGroupFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageReportedGroupAbsenceFailure {
    Marker,
    Identity,
    Snapshot,
    Residue,
}

impl PackageReportedGroupAbsenceFailure {
    const fn marker(self) -> &'static str {
        match self {
            Self::Marker => "recovery.group-absence-failed.marker",
            Self::Identity => "recovery.group-absence-failed.identity",
            Self::Snapshot => "recovery.group-absence-failed.snapshot",
            Self::Residue => "recovery.group-absence-failed.residue",
        }
    }
}

impl fmt::Display for PackageReportedGroupAbsenceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a reported package process-group absence proof failed")
    }
}

impl Error for PackageReportedGroupAbsenceFailure {}

fn wait_for_package_child_marker(
    path: &Path,
    deadline: Instant,
) -> Result<PackageChildMarker, Box<dyn Error>> {
    let bytes = wait_for_private_file(path, 64, deadline)?;
    let text = std::str::from_utf8(&bytes)?;
    let mut fields = text.split_whitespace();
    let pid = fields.next().and_then(|value| value.parse::<i32>().ok());
    let pgid = fields.next().and_then(|value| value.parse::<i32>().ok());
    if fields.next().is_some() || pid.is_none() || pgid.is_none() {
        return Err("package child marker was invalid".into());
    }
    let marker = PackageChildMarker {
        pid: pid.unwrap_or_default(),
        pgid: pgid.unwrap_or_default(),
    };
    if marker.pid <= 0 || marker.pgid <= 0 {
        return Err("package child marker identity was invalid".into());
    }
    Ok(marker)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PackageProcessState {
    pid: i32,
    process_group: i32,
    session: i32,
    user: u32,
    state: u8,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PackageProcessIdentity {
    pid: i32,
    process_group: i32,
    session: i32,
    user: u32,
}

impl PackageProcessState {
    const fn identity(self) -> PackageProcessIdentity {
        PackageProcessIdentity {
            pid: self.pid,
            process_group: self.process_group,
            session: self.session,
            user: self.user,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageProcessSnapshotError {
    Unstable,
    Empty,
    Leader,
    DuplicateProcess,
    Identity,
    LiveState,
    StoppedState,
    MissingStoppedMember,
}

impl fmt::Display for PackageProcessSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unstable => "package process snapshots were not stable",
            Self::Empty => "package process snapshot was empty",
            Self::Leader => "package process snapshot omitted its exact leader",
            Self::DuplicateProcess => "package process snapshot repeated one process",
            Self::Identity => "package process snapshot changed its job identity",
            Self::LiveState => "package process snapshot contained a non-live state",
            Self::StoppedState => "package process snapshot contained a non-stopped state",
            Self::MissingStoppedMember => {
                "package process snapshot omitted a stopped-generation member"
            }
        })
    }
}

impl Error for PackageProcessSnapshotError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageLiveSnapshotFailureState {
    NoObservation,
    Consistent(PackageProcessSnapshotError),
    Mixed,
}

impl PackageLiveSnapshotFailureState {
    fn observe(self, error: PackageProcessSnapshotError) -> Self {
        match self {
            Self::NoObservation => Self::Consistent(error),
            Self::Consistent(previous) if previous == error => self,
            Self::Consistent(_) | Self::Mixed => Self::Mixed,
        }
    }

    fn failure(self) -> PackageOfficialTuiGroupFailure {
        match self {
            Self::NoObservation => PackageOfficialTuiGroupFailure::NotStablyLiveNoObservation,
            Self::Consistent(error) => PackageOfficialTuiGroupFailure::NotStablyLive(error),
            Self::Mixed => PackageOfficialTuiGroupFailure::NotStablyLiveMixed,
        }
    }
}

const fn package_process_state_is_live(state: u8) -> bool {
    matches!(state, b'D' | b'I' | b'P' | b'R' | b'S' | b'U' | b'W')
}

fn validate_official_tui_snapshot_domain(
    tui: PackageChildMarker,
    members: &[PackageProcessState],
    expected_user: u32,
) -> Result<(), PackageProcessSnapshotError> {
    if members.is_empty() {
        return Err(PackageProcessSnapshotError::Empty);
    }
    if tui.pid <= 0 || tui.pid != tui.pgid {
        return Err(PackageProcessSnapshotError::Leader);
    }
    let mut pids = std::collections::BTreeSet::new();
    let mut leader_present = false;
    for member in members {
        if member.pid <= 0
            || member.process_group != tui.pgid
            || member.session != tui.pid
            || member.user != expected_user
        {
            return Err(PackageProcessSnapshotError::Identity);
        }
        if !pids.insert(member.pid) {
            return Err(PackageProcessSnapshotError::DuplicateProcess);
        }
        leader_present |= member.pid == tui.pid;
    }
    if !leader_present {
        return Err(PackageProcessSnapshotError::Leader);
    }
    Ok(())
}

fn validate_live_official_tui_snapshot(
    tui: PackageChildMarker,
    members: &[PackageProcessState],
    expected_user: u32,
) -> Result<(), PackageProcessSnapshotError> {
    validate_official_tui_snapshot_domain(tui, members, expected_user)?;
    if members
        .iter()
        .all(|member| package_process_state_is_live(member.state))
    {
        Ok(())
    } else {
        Err(PackageProcessSnapshotError::LiveState)
    }
}

fn validate_stopped_official_tui_snapshot(
    tui: PackageChildMarker,
    members: &[PackageProcessState],
    expected_user: u32,
) -> Result<(), PackageProcessSnapshotError> {
    validate_official_tui_snapshot_domain(tui, members, expected_user)?;
    if members.iter().all(|member| member.state == b'T') {
        Ok(())
    } else {
        Err(PackageProcessSnapshotError::StoppedState)
    }
}

fn validate_resumed_official_tui_snapshot(
    tui: PackageChildMarker,
    stopped_generation: &[PackageProcessState],
    resumed: &[PackageProcessState],
    expected_user: u32,
) -> Result<(), PackageProcessSnapshotError> {
    validate_stopped_official_tui_snapshot(tui, stopped_generation, expected_user)?;
    validate_live_official_tui_snapshot(tui, resumed, expected_user)?;
    for stopped in stopped_generation {
        let resumed_member = resumed
            .iter()
            .find(|member| member.pid == stopped.pid)
            .ok_or(PackageProcessSnapshotError::MissingStoppedMember)?;
        if resumed_member.identity() != stopped.identity() {
            return Err(PackageProcessSnapshotError::Identity);
        }
    }
    Ok(())
}

fn validate_stable_live_official_tui_snapshots(
    tui: PackageChildMarker,
    first: &[PackageProcessState],
    second: &[PackageProcessState],
    expected_user: u32,
) -> Result<(), PackageProcessSnapshotError> {
    if first != second {
        return Err(PackageProcessSnapshotError::Unstable);
    }
    validate_live_official_tui_snapshot(tui, first, expected_user)
}

fn validate_stable_resumed_official_tui_snapshots(
    tui: PackageChildMarker,
    stopped_generation: &[PackageProcessState],
    first: &[PackageProcessState],
    second: &[PackageProcessState],
    expected_user: u32,
) -> Result<(), PackageProcessSnapshotError> {
    if first != second {
        return Err(PackageProcessSnapshotError::Unstable);
    }
    validate_resumed_official_tui_snapshot(tui, stopped_generation, first, expected_user)
}

fn package_process_group_snapshot(
    process_group: i32,
) -> Result<Vec<PackageProcessState>, Box<dyn Error>> {
    if process_group <= 0 {
        return Err("package process group was invalid".into());
    }
    let output = Command::new("/bin/ps")
        .args(["-axo", PACKAGE_PS_PROCESS_FIELDS])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.len() > MAX_HTTP_REQUEST_BYTES {
        return Err("package process snapshot failed or exceeded its bound".into());
    }
    parse_package_process_group_snapshot_with_job_identity(
        &output.stdout,
        process_group,
        package_process_session_identity,
    )
}

fn package_process_session_identity(
    pid: i32,
    expected_process_group: i32,
) -> Result<i32, Box<dyn Error>> {
    let pid = rustix::process::Pid::from_raw(pid).ok_or("package process PID was invalid")?;
    let process_group = rustix::process::getpgid(Some(pid))?.as_raw_pid();
    if process_group != expected_process_group {
        return Err("package process group changed during its snapshot".into());
    }
    Ok(rustix::process::getsid(Some(pid))?.as_raw_pid())
}

fn parse_package_process_group_snapshot_with_job_identity<ResolveJobIdentity>(
    output: &[u8],
    process_group: i32,
    mut resolve_session: ResolveJobIdentity,
) -> Result<Vec<PackageProcessState>, Box<dyn Error>>
where
    ResolveJobIdentity: FnMut(i32, i32) -> Result<i32, Box<dyn Error>>,
{
    let mut members = Vec::new();
    for line in std::str::from_utf8(output)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let pid = fields
            .next()
            .ok_or("package process snapshot omitted PID")?
            .parse::<i32>()?;
        let pgid = fields
            .next()
            .ok_or("package process snapshot omitted PGID")?
            .parse::<i32>()?;
        let user = parse_package_process_snapshot_uid(
            fields
                .next()
                .ok_or("package process snapshot omitted UID")?,
        )?;
        let state_field = fields
            .next()
            .ok_or("package process snapshot omitted state")?;
        let state = *state_field
            .as_bytes()
            .first()
            .ok_or("package process snapshot state was empty")?;
        if fields.next().is_some() {
            return Err("package process snapshot had trailing fields".into());
        }
        if pgid == process_group {
            let session = resolve_session(pid, pgid)?;
            members.push(PackageProcessState {
                pid,
                process_group: pgid,
                session,
                user,
                state,
            });
        }
    }
    members.sort_unstable();
    Ok(members)
}

#[cfg(target_os = "linux")]
fn parse_package_process_snapshot_uid(value: &str) -> Result<u32, std::num::ParseIntError> {
    value.parse::<u32>()
}

#[cfg(target_os = "macos")]
fn parse_package_process_snapshot_uid(value: &str) -> Result<u32, std::num::ParseIntError> {
    value
        .parse::<u32>()
        .or_else(|_| value.parse::<i32>().map(|user| user as u32))
}

fn validate_official_tui_group(
    tui: PackageChildMarker,
    deadline: Instant,
) -> Result<(), PackageOfficialTuiGroupFailure> {
    validate_official_tui_job_identity(tui)?;
    let empty = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
    let proof = retry_package_official_tui_descriptor_scan(
        deadline,
        |attempt_deadline| {
            calcifer_unix_child_fd::verify_process_group_forbidden_descriptors_absent_before(
                tui.pgid,
                &empty,
                attempt_deadline,
            )
        },
        || validate_official_tui_job_identity(tui),
        thread::sleep,
        Instant::now,
    )?;
    if proof.member_count() == 0 {
        return Err(PackageOfficialTuiGroupFailure::Empty);
    }
    validate_live_official_tui_group(tui, deadline)
}

fn validate_official_tui_job_identity(
    tui: PackageChildMarker,
) -> Result<(), PackageOfficialTuiGroupFailure> {
    if tui.pid != tui.pgid {
        return Err(PackageOfficialTuiGroupFailure::Leader);
    }
    let pid = rustix::process::Pid::from_raw(tui.pid)
        .ok_or(PackageOfficialTuiGroupFailure::JobIdentity)?;
    if rustix::process::getpgid(Some(pid))
        .map_err(|_| PackageOfficialTuiGroupFailure::JobIdentity)?
        .as_raw_pid()
        != tui.pgid
        || rustix::process::getsid(Some(pid))
            .map_err(|_| PackageOfficialTuiGroupFailure::JobIdentity)?
            .as_raw_pid()
            != tui.pid
    {
        return Err(PackageOfficialTuiGroupFailure::JobIdentity);
    }
    Ok(())
}

fn retry_package_official_tui_descriptor_scan<T, Observe, Validate, Wait, Now>(
    deadline: Instant,
    mut observe: Observe,
    mut validate_job_identity: Validate,
    mut wait: Wait,
    mut now: Now,
) -> Result<T, PackageOfficialTuiGroupFailure>
where
    Observe: FnMut(Instant) -> Result<T, calcifer_unix_child_fd::ProcessGroupDescriptorScanError>,
    Validate: FnMut() -> Result<(), PackageOfficialTuiGroupFailure>,
    Wait: FnMut(Duration),
    Now: FnMut() -> Instant,
{
    use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

    loop {
        if now() >= deadline {
            return Err(PackageOfficialTuiGroupFailure::Descriptor(
                ProcessGroupDescriptorScanError::Deadline,
            ));
        }
        validate_job_identity()?;
        match observe(deadline) {
            Ok(proof) => {
                validate_job_identity()?;
                if now() >= deadline {
                    return Err(PackageOfficialTuiGroupFailure::Descriptor(
                        ProcessGroupDescriptorScanError::Deadline,
                    ));
                }
                return Ok(proof);
            }
            Err(
                ProcessGroupDescriptorScanError::ProcessChanged
                | ProcessGroupDescriptorScanError::DescriptorChanged,
            ) => {
                // The official TUI opens and closes ordinary descriptors while
                // it finishes startup. A torn double snapshot is expected
                // churn, not evidence that a forbidden authority crossed the
                // boundary. Retry only while the reported TUI PID/PGID/SID
                // tuple remains live on both sides of every attempt. Every
                // policy, permission, bound, unsupported-kind, and forbidden
                // descriptor failure remains immediately fatal.
                validate_job_identity()?;
                if !wait_before_next_bounded_observation(deadline, &mut wait, &mut now) {
                    return Err(PackageOfficialTuiGroupFailure::Descriptor(
                        ProcessGroupDescriptorScanError::Deadline,
                    ));
                }
            }
            Err(error) => return Err(PackageOfficialTuiGroupFailure::Descriptor(error)),
        }
    }
}

fn validate_live_official_tui_group(
    tui: PackageChildMarker,
    deadline: Instant,
) -> Result<(), PackageOfficialTuiGroupFailure> {
    let current_user = rustix::process::geteuid().as_raw();
    validate_live_official_tui_group_with_snapshot_observer(
        tui,
        deadline,
        current_user,
        package_process_group_snapshot,
        thread::sleep,
        Instant::now,
    )
}

fn wait_before_next_bounded_observation<Wait, Now>(
    deadline: Instant,
    wait: &mut Wait,
    now: &mut Now,
) -> bool
where
    Wait: FnMut(Duration),
    Now: FnMut() -> Instant,
{
    let observed_at = now();
    let remaining = deadline.saturating_duration_since(observed_at);
    if remaining.is_zero() {
        return false;
    }
    wait(remaining.min(Duration::from_millis(50)));
    now() < deadline
}

fn validate_live_official_tui_group_with_snapshot_observer<Observe, Wait, Now>(
    tui: PackageChildMarker,
    deadline: Instant,
    current_user: u32,
    mut observe: Observe,
    mut wait: Wait,
    mut now: Now,
) -> Result<(), PackageOfficialTuiGroupFailure>
where
    Observe: FnMut(i32) -> Result<Vec<PackageProcessState>, Box<dyn Error>>,
    Wait: FnMut(Duration),
    Now: FnMut() -> Instant,
{
    let mut failure_state = PackageLiveSnapshotFailureState::NoObservation;
    let mut snapshot_observation_failed = false;
    while now() < deadline {
        let first = match observe(tui.pgid) {
            Ok(first) => first,
            Err(_) => {
                snapshot_observation_failed = true;
                if !wait_before_next_bounded_observation(deadline, &mut wait, &mut now) {
                    break;
                }
                continue;
            }
        };
        if now() >= deadline || !wait_before_next_bounded_observation(deadline, &mut wait, &mut now)
        {
            break;
        }
        let second = match observe(tui.pgid) {
            Ok(second) => second,
            Err(_) => {
                snapshot_observation_failed = true;
                if !wait_before_next_bounded_observation(deadline, &mut wait, &mut now) {
                    break;
                }
                continue;
            }
        };
        if now() >= deadline {
            break;
        }
        snapshot_observation_failed = false;
        match validate_stable_live_official_tui_snapshots(tui, &first, &second, current_user) {
            Ok(()) => return Ok(()),
            Err(error) => failure_state = failure_state.observe(error),
        }
    }
    if snapshot_observation_failed {
        Err(PackageOfficialTuiGroupFailure::Snapshot)
    } else {
        Err(failure_state.failure())
    }
}

fn validate_resumed_official_tui_group(
    tui: PackageChildMarker,
    stopped_generation: &[PackageProcessState],
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    let current_user = rustix::process::geteuid().as_raw();
    while Instant::now() < deadline {
        let first = package_process_group_snapshot(tui.pgid)?;
        thread::sleep(Duration::from_millis(50));
        let second = package_process_group_snapshot(tui.pgid)?;
        if validate_stable_resumed_official_tui_snapshots(
            tui,
            stopped_generation,
            &first,
            &second,
            current_user,
        )
        .is_ok()
        {
            return Ok(());
        }
    }
    Err("official TUI process group did not become stably resumed".into())
}

fn wait_for_stable_stopped_package_group(
    process_group: i32,
    deadline: Instant,
) -> Result<Vec<PackageProcessState>, Box<dyn Error>> {
    while Instant::now() < deadline {
        let first = package_process_group_snapshot(process_group)?;
        thread::sleep(Duration::from_millis(50));
        let second = package_process_group_snapshot(process_group)?;
        let current_user = rustix::process::geteuid().as_raw();
        if !first.is_empty()
            && first == second
            && first
                .iter()
                .all(|member| member.user == current_user && member.state == b'T')
        {
            return Ok(first);
        }
    }
    Err("package process group did not become stably stopped".into())
}

fn wait_for_package_child(
    child: &mut Child,
    deadline: Instant,
) -> Result<std::process::ExitStatus, Box<dyn Error>> {
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err("package coordinator exact wait exceeded its deadline".into())
}

fn wait_for_package_pid_gone(
    child: PackageChildMarker,
    deadline: Instant,
) -> Result<(), PackageReportedGroupAbsenceFailure> {
    while Instant::now() < deadline {
        let identity = observe_process_job_identity(child.pid)
            .map_err(|_| PackageReportedGroupAbsenceFailure::Identity)?;
        let group = package_process_group_snapshot(child.pgid)
            .map_err(|_| PackageReportedGroupAbsenceFailure::Snapshot)?;
        if identity.is_none_or(|(pgid, _)| pgid != child.pgid) && group.is_empty() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(PackageReportedGroupAbsenceFailure::Residue)
}

/// Reported process identities are observation-only. Cleanup succeeds only
/// after every required fixed marker parses and its exact PID/PGID is absent;
/// this function has no signaling authority.
fn verify_reported_package_groups_absent(
    report: &Path,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    for (child_marker, not_started_marker) in [
        ("tui.child", PACKAGED_TUI_NOT_STARTED_MARKER),
        ("app.child", PACKAGED_APP_NOT_STARTED_MARKER),
    ] {
        verify_reported_package_child_slot_absent(
            report,
            child_marker,
            not_started_marker,
            deadline,
        )?;
    }
    verify_reported_package_group_absent(report, "guardian.child", deadline)?;
    Ok(())
}

fn verify_reported_package_child_slot_absent(
    report: &Path,
    child_marker: &str,
    not_started_marker: &str,
    deadline: Instant,
) -> Result<(), PackageReportedGroupAbsenceFailure> {
    let child_path = report.join(child_marker);
    let not_started_path = report.join(not_started_marker);
    let child_exists = match fs::symlink_metadata(&child_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return Err(PackageReportedGroupAbsenceFailure::Marker),
    };
    let not_started_exists = match fs::symlink_metadata(&not_started_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return Err(PackageReportedGroupAbsenceFailure::Marker),
    };
    if child_exists == not_started_exists {
        return Err(PackageReportedGroupAbsenceFailure::Marker);
    }
    if child_exists {
        return verify_reported_package_group_absent(report, child_marker, deadline);
    }
    match read_private_bounded(&not_started_path, b"classified\n".len()) {
        Ok(bytes) if bytes == b"classified\n" => Ok(()),
        Ok(_) | Err(_) => Err(PackageReportedGroupAbsenceFailure::Marker),
    }
}

fn verify_reported_package_group_absent(
    report: &Path,
    marker_name: &str,
    deadline: Instant,
) -> Result<(), PackageReportedGroupAbsenceFailure> {
    let child = wait_for_package_child_marker(&report.join(marker_name), deadline)
        .map_err(|_| PackageReportedGroupAbsenceFailure::Marker)?;
    wait_for_package_pid_gone(child, deadline)
}

fn verify_package_runtime_empty(runtime_parent: &Path) -> Result<(), Box<dyn Error>> {
    validate_packaged_runtime_parent(runtime_parent)?;
    if fs::read_dir(runtime_parent)?.next().transpose()?.is_some() {
        Err("production session runtime residue remained after cleanup".into())
    } else {
        Ok(())
    }
}

fn verify_package_build_namespaces_empty(root: &Path) -> Result<(), Box<dyn Error>> {
    verify_package_runtime_empty(&root.join("r"))?;
    let stage_parent = root.join("s");
    let metadata = fs::symlink_metadata(&stage_parent)?;
    if fs::canonicalize(&stage_parent)? != stage_parent
        || stage_parent.parent() != Some(root)
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("package compatibility stage parent identity changed".into());
    }
    if fs::read_dir(&stage_parent)?.next().transpose()?.is_some() {
        Err("package compatibility stage residue remained after cleanup".into())
    } else {
        Ok(())
    }
}

/// Exercises Calcifer's exact one-SIGTERM App shutdown against a real running
/// turn in the official checksum-pinned package. The fake provider is
/// loopback-only, receives no credential, and returns no user-controlled data.
#[test]
#[ignore = "requires the checksum-pinned official Codex 0.144.4 package"]
fn packaged_codex_running_turn_obeys_the_pinned_graceful_drain_contract()
-> Result<(), Box<dyn Error>> {
    let executable = package_binary()?;
    let scratch = PackageScratch::create()?;
    let provider = match DelayedProvider::spawn() {
        Ok(provider) => provider,
        Err(error) => {
            scratch.cleanup()?;
            return Err(error);
        }
    };
    if let Err(error) = write_test_config(&scratch.codex_home, provider.address()) {
        let _ = provider.cancel_and_join();
        scratch.cleanup()?;
        return Err(error);
    }

    let socket_path = scratch.root.join("app.sock");
    let command = packaged_app_command(&executable, &scratch, &socket_path);
    let app = match ManagedGroupChild::spawn(ChildRole::AppServer, command, false) {
        Ok(app) => app,
        Err(_) => {
            let _ = provider.cancel_and_join();
            scratch.cleanup()?;
            return Err("official App Server did not start".into());
        }
    };
    let client = match start_running_turn(&socket_path, &scratch, &provider) {
        Ok(client) => client,
        Err(error) => return cleanup_setup_failure(app, provider, scratch, error),
    };

    let (drain_sender, drain_receiver) = mpsc::sync_channel(1);
    let drain_worker = thread::Builder::new()
        .name("calcifer-package-app-drain".to_owned())
        .spawn(move || {
            let result = shutdown_app_server_child(app, PROCESS_TIMEOUT, PROCESS_TIMEOUT);
            let _ = drain_sender.send(result);
        })?;

    match drain_receiver.recv_timeout(GRACE_OBSERVATION) {
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        Ok(result) => {
            let _ = provider.release_response();
            let _ = provider.join();
            drain_worker
                .join()
                .map_err(|_| "App Server drain worker panicked")?;
            return finish_unexpected_early_drain(result, scratch);
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = provider.release_response();
            let _ = provider.join();
            return Err("App Server drain worker disappeared".into());
        }
    }

    let release_error = provider.release_response().err();
    let (drain_result, exceeded_outer_deadline) =
        match drain_receiver.recv_timeout(PROCESS_TIMEOUT + PROCESS_TIMEOUT + IO_TIMEOUT) {
            Ok(result) => (result, false),
            Err(mpsc::RecvTimeoutError::Timeout) => (
                // Keep waiting authority and the process owner alive. The CI job
                // timeout is the final fail-closed boundary if an upstream build
                // violates Calcifer's bounded shutdown assumption.
                drain_receiver
                    .recv()
                    .map_err(|_| "App Server drain worker disappeared after its deadline")?,
                true,
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("App Server drain worker disappeared".into());
            }
        };
    drain_worker
        .join()
        .map_err(|_| "App Server drain worker panicked")?;
    let drained = match drain_result {
        Ok(drained) => drained,
        Err(mut unreaped) => match unreaped.retry_app_server(PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
            Ok(drained) => drained,
            Err(_) => unreaped.park(),
        },
    };

    assert_eq!(drained.outcome().failure(), None);
    assert!(matches!(
        drained.outcome().children().app_server(),
        ChildDisposition::Exited {
            code: 0,
            stop_action: StopAction::Term,
        }
    ));
    let provider_result = provider.join();
    drop(client);
    scratch.cleanup()?;
    provider_result?;
    if exceeded_outer_deadline {
        return Err("App Server did not finish within the outer shutdown deadline".into());
    }
    if release_error.is_some() {
        return Err("fake provider response worker disappeared".into());
    }
    Ok(())
}

/// Exercises the official host-local shell escape hatch, whose child calls
/// `setsid(2)`, and proves that Calcifer's authority descriptors and ambient
/// credential variables do not cross either exec boundary.
#[test]
#[ignore = "requires the checksum-pinned official Codex 0.144.4 package"]
fn packaged_codex_detached_tool_inherits_no_calcifer_authority() -> Result<(), Box<dyn Error>> {
    let executable = package_binary()?;
    let scratch = PackageScratch::create()?;
    let authorities = match SupervisorAuthorityDescriptors::create(&scratch) {
        Ok(authorities) => authorities,
        Err(error) => {
            scratch.cleanup()?;
            return Err(error);
        }
    };
    let provider = match DelayedProvider::spawn() {
        Ok(provider) => provider,
        Err(error) => {
            drop(authorities);
            scratch.cleanup()?;
            return Err(error);
        }
    };
    if let Err(error) = write_test_config(&scratch.codex_home, provider.address()) {
        let _ = provider.cancel_and_join();
        drop(authorities);
        scratch.cleanup()?;
        return Err(error);
    }

    let socket_path = scratch.root.join("tool-app.sock");
    let command = packaged_app_command(&executable, &scratch, &socket_path);
    let mut app = match ManagedGroupChild::spawn(ChildRole::AppServer, command, false) {
        Ok(app) => app,
        Err(_) => {
            let _ = provider.cancel_and_join();
            drop(authorities);
            scratch.cleanup()?;
            return Err("official App Server did not start".into());
        }
    };

    let release_path = scratch.root.join("tool.release");
    let lifetime = match ToolLifetimeProbe::create(&scratch.root.join("tool.lifetime.lock")) {
        Ok(lifetime) => lifetime,
        Err(error) => {
            drop(authorities);
            return cleanup_setup_failure(app, provider, scratch, error);
        }
    };
    let mut launch_state = DetachedToolLaunchState::NotRequested;
    let client = match run_detached_tool_probe(
        &mut app,
        &socket_path,
        &scratch,
        &authorities,
        &release_path,
        &lifetime,
        &mut launch_state,
    ) {
        Ok(client) => client,
        Err(error) => {
            return cleanup_tool_probe_failure(
                ToolProbeFailureContext {
                    app,
                    provider,
                    scratch,
                    authorities,
                    lifetime,
                    launch_state,
                },
                &release_path,
                error,
            );
        }
    };

    let drained = match shutdown_app_server_child(app, PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
        Ok(drained) => drained,
        Err(mut unreaped) => match unreaped.retry_app_server(PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
            Ok(drained) => drained,
            Err(_) => unreaped.park(),
        },
    };
    assert_eq!(drained.outcome().failure(), None);
    assert!(matches!(
        drained.outcome().children().app_server(),
        ChildDisposition::Exited {
            code: 0,
            stop_action: StopAction::Term,
        }
    ));
    // The exact direct-child wait above is identity-bound App absence proof;
    // the detached tool's independent process-lifetime lock and PID absence
    // observation completed before `run_detached_tool_probe` returned.
    let provider_result = provider.cancel_and_join();
    drop(client);
    drop(authorities);
    drop(lifetime);
    scratch.cleanup()?;
    provider_result?;
    Ok(())
}

/// Runs Calcifer's typed monitor state machine against the real packaged App
/// Server. The ChatGPT-shaped credential is synthetic, private to this test,
/// and accepted only by a loopback backend that verifies the exact headers.
#[test]
#[ignore = "requires the checksum-pinned official Codex 0.144.4 package"]
fn packaged_codex_typed_monitor_accepts_usage_and_redacts_provider_failure()
-> Result<(), Box<dyn Error>> {
    let executable = package_binary()?;
    let scratch = PackageScratch::create()?;
    let backend = match RateLimitBackend::spawn() {
        Ok(backend) => backend,
        Err(error) => {
            scratch.cleanup()?;
            return Err(error);
        }
    };
    if let Err(error) = write_usage_test_profile(&scratch.codex_home, backend.address()) {
        let _ = backend.cancel_and_join();
        scratch.cleanup()?;
        return Err(error);
    }

    let socket_path = scratch.root.join("monitor-app.sock");
    let command = packaged_app_command(&executable, &scratch, &socket_path);
    let app = match ManagedGroupChild::spawn(ChildRole::AppServer, command, false) {
        Ok(app) => app,
        Err(_) => {
            let _ = backend.cancel_and_join();
            scratch.cleanup()?;
            return Err("official App Server did not start".into());
        }
    };
    let mut client = match connect_app_server(&socket_path, Instant::now() + IO_TIMEOUT) {
        Ok(client) => client,
        Err(error) => return cleanup_usage_setup_failure(app, backend, scratch, error),
    };

    let monitor_result = exercise_packaged_typed_monitor(&mut client, &scratch.codex_home);
    let backend_result = if monitor_result.is_ok() {
        backend.join()
    } else {
        backend.cancel_and_join()
    };

    let drained = match shutdown_app_server_child(app, PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
        Ok(drained) => drained,
        Err(mut unreaped) => match unreaped.retry_app_server(PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
            Ok(drained) => drained,
            Err(_) => unreaped.park(),
        },
    };
    if drained.outcome().failure().is_some()
        || !matches!(
            drained.outcome().children().app_server(),
            ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::Term,
            }
        )
    {
        return Err("official App Server violated the pinned graceful drain contract".into());
    }
    drop(client);
    scratch.cleanup()?;
    backend_result?;
    monitor_result
}

fn exercise_packaged_typed_monitor(
    client: &mut PackageAppWebSocket,
    codex_home: &Path,
) -> Result<(), Box<dyn Error>> {
    let capability = MonitorSessionCapability::for_test(codex_home, PACKAGE_MONITOR_THREAD_ID)?;
    let (mut monitor, initialize) = MonitorProtocol::start_pinned(capability)?;
    send_monitor_command(client, &initialize)?;

    let initialize_response = receive_rpc_message(client, 0, Instant::now() + IO_TIMEOUT)?;
    let startup_actions = monitor.receive(&initialize_response)?;
    if startup_actions
        != vec![
            MonitorAction::Outbound(MonitorCommand::Initialized),
            MonitorAction::Outbound(MonitorCommand::ReadUsage { request_id: 1 }),
        ]
    {
        return Err("typed monitor emitted an unexpected startup sequence".into());
    }
    for action in startup_actions {
        let MonitorAction::Outbound(command) = action else {
            return Err("typed monitor published before its first usage read".into());
        };
        send_monitor_command(client, &command)?;
    }

    let usage_response = receive_rpc_message(client, 1, Instant::now() + IO_TIMEOUT)?;
    let usage_actions = monitor.receive(&usage_response)?;
    let usage = match usage_actions.as_slice() {
        [MonitorAction::PublishUsage(usage)] => usage.as_ref(),
        _ => return Err("typed monitor did not publish exactly one usage snapshot".into()),
    };
    let primary = usage
        .rate_limits
        .as_ref()
        .and_then(|limits| limits.primary.as_ref())
        .ok_or("typed monitor omitted the primary usage window")?;
    if primary.used_percent != 42
        || primary.remaining_percent != 58
        || primary.window_duration_mins != Some(60)
        || primary.resets_at != Some(1_735_689_720)
    {
        return Err("typed monitor normalized the primary usage window incorrectly".into());
    }
    let reset_credits = usage
        .reset_credits
        .as_ref()
        .ok_or("typed monitor omitted reset-credit availability")?;
    if reset_credits.available_count != 2 || reset_credits.details.as_ref().map(Vec::len) != Some(2)
    {
        return Err("typed monitor normalized reset-credit availability incorrectly".into());
    }
    let projected = serde_json::to_string(usage)?;
    for forbidden in [
        "calcifer-private-credit-id",
        "calcifer-private-title",
        "calcifer-private-description",
    ] {
        if projected.contains(forbidden) {
            return Err("typed monitor retained an opaque provider field".into());
        }
    }

    let refresh = monitor.request_refresh()?;
    if refresh
        != vec![MonitorAction::Outbound(MonitorCommand::ReadUsage {
            request_id: 2,
        })]
    {
        return Err("typed monitor emitted an unexpected refresh sequence".into());
    }
    let MonitorAction::Outbound(command) = &refresh[0] else {
        return Err("typed monitor refresh did not emit a read".into());
    };
    send_monitor_command(client, command)?;

    let provider_failure = receive_rpc_message(client, 2, Instant::now() + IO_TIMEOUT)?;
    let error = match monitor.receive(&provider_failure) {
        Ok(_) => return Err("the second synthetic backend response was accepted".into()),
        Err(error) => error,
    };
    if error != MonitorError::Usage(CodexUsageError::Provider)
        || monitor.latest_usage().is_some()
        || error.to_string().contains("calcifer-private-provider-body")
    {
        return Err("typed monitor did not fail closed with a redacted provider error".into());
    }
    Ok(())
}

fn send_monitor_command<S: Read + Write>(
    websocket: &mut WebSocket<S>,
    command: &MonitorCommand,
) -> Result<(), Box<dyn Error>> {
    let encoded = command.encode()?;
    if encoded.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
        return Err("typed monitor command exceeded the package bound".into());
    }
    websocket.send(Message::text(String::from_utf8(encoded)?))?;
    Ok(())
}

fn receive_rpc_message<S: Read + Write>(
    websocket: &mut WebSocket<S>,
    expected_id: u64,
    deadline: Instant,
) -> Result<Vec<u8>, Box<dyn Error>> {
    loop {
        if Instant::now() >= deadline {
            return Err("typed monitor response exceeded its deadline".into());
        }
        match websocket.read() {
            Ok(Message::Text(text)) => {
                if text.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
                    return Err("typed monitor response exceeded its bound".into());
                }
                let envelope: Value = serde_json::from_slice(text.as_bytes())?;
                if envelope.get("id").and_then(Value::as_u64) == Some(expected_id) {
                    return Ok(text.as_bytes().to_vec());
                }
            }
            Ok(Message::Ping(bytes)) => websocket.send(Message::Pong(bytes))?,
            Ok(Message::Close(_)) => return Err("official App Server disconnected".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn cleanup_usage_setup_failure(
    app: ManagedGroupChild,
    backend: RateLimitBackend,
    scratch: PackageScratch,
    original: Box<dyn Error>,
) -> Result<(), Box<dyn Error>> {
    let _ = backend.cancel_and_join();
    match shutdown_app_server_child(app, PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
        Ok(_) => {
            scratch.cleanup()?;
            Err(original)
        }
        Err(mut unreaped) => unreaped.park(),
    }
}

fn run_detached_tool_probe(
    app: &mut ManagedGroupChild,
    socket_path: &Path,
    scratch: &PackageScratch,
    authorities: &SupervisorAuthorityDescriptors,
    release_path: &Path,
    lifetime: &ToolLifetimeProbe,
    launch_state: &mut DetachedToolLaunchState,
) -> Result<PackageAppWebSocket, Box<dyn Error>> {
    let (client, thread_id) = start_idle_thread(socket_path, scratch)?;
    let forbidden = authorities.cross_process_set()?;
    let app_isolation = app
        .observe_forbidden_descriptors_absent_while_live(&forbidden, Instant::now() + IO_TIMEOUT)?;
    if app_isolation.member_count() == 0 || app_isolation.descriptor_count() < 3 {
        return Err("official App Server descriptor observation was incomplete".into());
    }
    drop(forbidden);

    let manifest_path = scratch.root.join("tool.manifest.json");
    let report_path = scratch.root.join("tool.report.json");
    let manifest = ToolProbeManifest {
        version: TOOL_PROBE_VERSION,
        identities: authorities.identities.clone(),
    };
    let encoded = serde_json::to_vec(&manifest)?;
    if encoded.len() > MAX_TOOL_PROBE_BYTES {
        return Err("tool probe manifest exceeded its bound".into());
    }
    write_private_new(&manifest_path, &encoded)?;

    let probe_command = tool_probe_command(
        &std::env::current_exe()?,
        &manifest_path,
        &report_path,
        release_path,
        lifetime.path(),
    )?;
    // Serialize and bound the one permitted tool request before touching the
    // WebSocket. The consuming send boundary then classifies only observed
    // transport bytes and drops the socket on every error.
    let request = PreparedToolRequest::shell_command(thread_id, probe_command)?;
    let sent = match send_prepared_tool_request(client, request) {
        Ok(sent) => sent,
        Err(failure) => {
            *launch_state = failure.launch_state();
            return Err(failure.into());
        }
    };
    *launch_state = sent.launch_state();
    let mut client = sent.into_websocket();
    let response = receive_result(&mut client, 3, Instant::now() + IO_TIMEOUT)?;
    if response.as_object().is_none_or(|object| !object.is_empty()) {
        return Err("thread/shellCommand response contract drifted".into());
    }

    let report = wait_for_tool_probe_report(&report_path, Instant::now() + IO_TIMEOUT)?;
    let report_is_valid = report.version == TOOL_PROBE_VERSION
        && report.pid > 0
        && report.pid == report.process_group
        && report.pid == report.session
        && report.forbidden_descriptor_matches == 0
        && !report.denied_environment_present;
    if !report_is_valid {
        return Err("detached tool isolation proof failed".into());
    }
    lifetime.assert_held_by_reported_tool()?;
    assert_reported_tool_is_live(&report)?;
    write_private_new(release_path, b"release\n")?;
    lifetime.wait_until_released(Instant::now() + PROCESS_TIMEOUT)?;
    wait_for_reported_tool_pid_gone(&report, Instant::now() + PROCESS_TIMEOUT)?;
    Ok(client)
}

fn start_idle_thread(
    socket_path: &Path,
    scratch: &PackageScratch,
) -> Result<(PackageAppWebSocket, String), Box<dyn Error>> {
    let mut client = connect_app_server(socket_path, Instant::now() + IO_TIMEOUT)?;
    send_request(
        &mut client,
        1,
        "initialize",
        json!({
            "clientInfo": {
                "name": "calcifer",
                "title": "Calcifer package smoke",
                "version": env!("CARGO_PKG_VERSION")
            },
            "capabilities": { "experimentalApi": false }
        }),
    )?;
    let initialize = receive_result(&mut client, 1, Instant::now() + IO_TIMEOUT)?;
    require_pinned_initialize(&initialize, &scratch.codex_home)?;
    send_request(
        &mut client,
        2,
        "thread/start",
        json!({
            "cwd": scratch.workspace,
            "model": "calcifer-package-smoke",
            "modelProvider": "calcifer_package_smoke",
            "approvalPolicy": "never",
            "sandbox": "read-only",
            "ephemeral": true
        }),
    )?;
    let started = receive_result(&mut client, 2, Instant::now() + IO_TIMEOUT)?;
    let thread_id = bounded_thread_id(&started)?;
    Ok((client, thread_id))
}

struct ToolProbeFailureContext {
    app: ManagedGroupChild,
    provider: DelayedProvider,
    scratch: PackageScratch,
    authorities: SupervisorAuthorityDescriptors,
    lifetime: ToolLifetimeProbe,
    launch_state: DetachedToolLaunchState,
}

fn cleanup_tool_probe_failure(
    context: ToolProbeFailureContext,
    release_path: &Path,
    original: Box<dyn Error>,
) -> Result<(), Box<dyn Error>> {
    let ToolProbeFailureContext {
        app,
        provider,
        scratch,
        authorities,
        lifetime,
        launch_state,
    } = context;
    ensure_tool_release(release_path);
    let _ = provider.cancel_and_join();
    match shutdown_app_server_child(app, PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
        Ok(_) => finish_tool_probe_failure_cleanup(
            authorities,
            lifetime,
            scratch,
            launch_state,
            original,
        ),
        Err(mut unreaped) => match unreaped.retry_app_server(PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
            Ok(_) => finish_tool_probe_failure_cleanup(
                authorities,
                lifetime,
                scratch,
                launch_state,
                original,
            ),
            Err(_) => unreaped.park(),
        },
    }
}

fn finish_tool_probe_failure_cleanup(
    authorities: SupervisorAuthorityDescriptors,
    lifetime: ToolLifetimeProbe,
    scratch: PackageScratch,
    launch_state: DetachedToolLaunchState,
    original: Box<dyn Error>,
) -> Result<(), Box<dyn Error>> {
    match detached_tool_failure_cleanup_decision(launch_state) {
        DetachedToolFailureCleanupDecision::Finite => {
            drop(authorities);
            drop(lifetime);
            scratch.cleanup()?;
            return Err(original);
        }
        DetachedToolFailureCleanupDecision::RequireProcessProofOrPark => {}
    }

    // App absence closes the only future spawn source, but an already-detached
    // tool may still be descheduled before taking its lifetime lock or
    // publishing its PID. Only a valid report followed by both lock release
    // and exact PID/PGID/SID absence permits scratch cleanup. Missing or
    // malformed evidence is permanently ambiguous and therefore retained.
    let report_path = scratch.root.join("tool.report.json");
    let cleanup_is_proven =
        wait_for_tool_probe_report(&report_path, Instant::now() + PROCESS_TIMEOUT)
            .ok()
            .filter(tool_probe_report_has_process_identity)
            .is_some_and(|report| {
                lifetime
                    .wait_until_released(Instant::now() + PROCESS_TIMEOUT)
                    .and_then(|()| {
                        wait_for_reported_tool_pid_gone(&report, Instant::now() + PROCESS_TIMEOUT)
                    })
                    .is_ok()
            });
    if !cleanup_is_proven {
        park_ambiguous_tool_probe_cleanup(authorities, lifetime, scratch);
    }

    drop(authorities);
    drop(lifetime);
    scratch.cleanup()?;
    Err(original)
}

fn tool_probe_report_has_process_identity(report: &ToolProbeReport) -> bool {
    report.version == TOOL_PROBE_VERSION
        && report.pid > 0
        && report.pid == report.process_group
        && report.pid == report.session
}

fn park_ambiguous_tool_probe_cleanup(
    authorities: SupervisorAuthorityDescriptors,
    lifetime: ToolLifetimeProbe,
    scratch: PackageScratch,
) -> ! {
    // Preserve every source-pinned authority and the private evidence root.
    // Returning would let a report-less detached process outlive its proof
    // state; the test runner/job timeout is the final process-tree boundary.
    std::mem::forget(authorities);
    std::mem::forget(lifetime);
    std::mem::forget(scratch);
    loop {
        thread::park();
    }
}

fn ensure_tool_release(path: &Path) {
    match write_private_new(path, b"release\n") {
        Ok(()) => {}
        Err(_) if path.is_file() => {}
        Err(_) => {}
    }
}

fn tool_probe_command(
    test_binary: &Path,
    manifest: &Path,
    report: &Path,
    release: &Path,
    lifetime: &Path,
) -> Result<String, Box<dyn Error>> {
    let binary = test_binary
        .to_str()
        .ok_or("tool probe test binary path was not UTF-8")?;
    let manifest = manifest
        .to_str()
        .ok_or("tool probe manifest path was not UTF-8")?;
    let report = report
        .to_str()
        .ok_or("tool probe report path was not UTF-8")?;
    let release = release
        .to_str()
        .ok_or("tool probe release path was not UTF-8")?;
    let lifetime = lifetime
        .to_str()
        .ok_or("tool probe lifetime path was not UTF-8")?;
    let arguments = [
        "/usr/bin/env".to_owned(),
        format!("{TOOL_PROBE_MAGIC_ENV}=v1"),
        format!("{TOOL_PROBE_MANIFEST_ENV}={manifest}"),
        format!("{TOOL_PROBE_REPORT_ENV}={report}"),
        format!("{TOOL_PROBE_RELEASE_ENV}={release}"),
        format!("{TOOL_PROBE_LIFETIME_ENV}={lifetime}"),
        binary.to_owned(),
        "--exact".to_owned(),
        TOOL_PROBE_CHILD_TEST.to_owned(),
        "--nocapture".to_owned(),
    ];
    Ok(format!(
        "exec {}",
        arguments
            .iter()
            .map(|argument| shell_quote(argument))
            .collect::<Vec<_>>()
            .join(" ")
    ))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn wait_for_tool_probe_report(
    path: &Path,
    deadline: Instant,
) -> Result<ToolProbeReport, Box<dyn Error>> {
    loop {
        match read_private_bounded(path, MAX_TOOL_PROBE_BYTES) {
            Ok(bytes) => return Ok(serde_json::from_slice(&bytes)?),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err("detached tool produced no isolation report".into());
        }
    }
}

#[test]
fn packaged_codex_detached_tool_probe_child() -> Result<(), Box<dyn Error>> {
    let Some(magic) = std::env::var_os(TOOL_PROBE_MAGIC_ENV) else {
        return Ok(());
    };
    if magic != OsStr::new("v1") {
        return Err("invalid package tool probe activation".into());
    }
    let manifest_path = required_probe_path(TOOL_PROBE_MANIFEST_ENV)?;
    let report_path = required_probe_path(TOOL_PROBE_REPORT_ENV)?;
    let release_path = required_probe_path(TOOL_PROBE_RELEASE_ENV)?;
    let lifetime_path = required_probe_path(TOOL_PROBE_LIFETIME_ENV)?;
    validate_probe_paths(&manifest_path, &report_path, &release_path, &lifetime_path)?;
    let manifest: ToolProbeManifest =
        serde_json::from_slice(&read_private_bounded(&manifest_path, MAX_TOOL_PROBE_BYTES)?)?;
    if manifest.version != TOOL_PROBE_VERSION
        || manifest.identities.len() != SUPERVISOR_AUTHORITY_DESCRIPTOR_COUNT
    {
        return Err("invalid tool probe manifest".into());
    }

    let mut forbidden_descriptor_matches = 0_usize;
    for identity in manifest.identities {
        forbidden_descriptor_matches = forbidden_descriptor_matches
            .checked_add(
                calcifer_unix_child_fd::count_open_descriptors_with_identity(
                    calcifer_unix_child_fd::DescriptorIdentity {
                        device: identity.device,
                        inode: identity.inode,
                    },
                )?,
            )
            .ok_or("tool probe descriptor count overflowed")?;
    }
    let denied_environment_present = MANAGED_ENVIRONMENT_DENYLIST
        .iter()
        .any(|name| std::env::var_os(name).is_some());
    let pid = rustix::process::getpid().as_raw_pid();
    let report = ToolProbeReport {
        version: TOOL_PROBE_VERSION,
        pid,
        process_group: rustix::process::getpgid(None)?.as_raw_pid(),
        session: rustix::process::getsid(None)?.as_raw_pid(),
        forbidden_descriptor_matches,
        denied_environment_present,
    };
    let lifetime = open_existing_private_file(&lifetime_path)?;
    FileExt::lock_exclusive(&lifetime)?;
    let encoded = serde_json::to_vec(&report)?;
    if encoded.len() > MAX_TOOL_PROBE_BYTES {
        return Err("tool probe report exceeded its bound".into());
    }
    let temporary = report_path.with_extension("json.pending");
    write_private_new(&temporary, &encoded)?;
    fs::rename(&temporary, &report_path)?;

    // This independent flock is the detached process's identity-bound exit
    // witness. Forgetting it is intentional: no Rust path can release it, so
    // the parent can acquire the lock only after the kernel destroys this
    // exact process and closes its descriptor table.
    std::mem::forget(lifetime);

    let deadline = Instant::now()
        .checked_add(PROCESS_TIMEOUT)
        .ok_or("tool probe release deadline overflowed")?;
    while Instant::now() < deadline {
        if release_path.is_file() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err("tool probe release timed out".into())
}

fn required_probe_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "tool probe path was missing or relative".into())
}

fn validate_probe_paths(
    manifest: &Path,
    report: &Path,
    release: &Path,
    lifetime: &Path,
) -> Result<(), Box<dyn Error>> {
    let root = manifest
        .parent()
        .ok_or("tool probe manifest had no parent")?;
    if report.parent() != Some(root)
        || release.parent() != Some(root)
        || lifetime.parent() != Some(root)
        || manifest.file_name() != Some(OsStr::new("tool.manifest.json"))
        || report.file_name() != Some(OsStr::new("tool.report.json"))
        || release.file_name() != Some(OsStr::new("tool.release"))
        || lifetime.file_name() != Some(OsStr::new("tool.lifetime.lock"))
        || fs::canonicalize(root)? != root
    {
        return Err("tool probe paths escaped their private root".into());
    }
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || read_private_bounded(&root.join("owner.marker"), 64)? != b"calcifer-package-smoke-v1\n"
    {
        return Err("tool probe private root identity was invalid".into());
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct ToolProbeIdentity {
    device: u64,
    inode: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ToolProbeManifest {
    version: u8,
    identities: Vec<ToolProbeIdentity>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ToolProbeReport {
    version: u8,
    pid: i32,
    process_group: i32,
    session: i32,
    forbidden_descriptor_matches: usize,
    denied_environment_present: bool,
}

/// Live instances of the same descriptor-bearing authorities retained by a
/// production supervisor generation. This deliberately contains no stand-in
/// files: A and B are real profile locks, and the remaining six descriptors
/// are the lifecycle, terminal-byte, and anchor-completion channels.
struct SupervisorAuthorityDescriptors {
    coordinator_lease: CoordinatorProfileLease,
    guardian_lease: TargetGuardianLease,
    lifecycle_coordinator: LifecycleEndpoint,
    lifecycle_guardian: LifecycleEndpoint,
    terminal_coordinator: TerminalEndpoint,
    terminal_guardian: TerminalEndpoint,
    anchor_completion: AnchorCompletion,
    guardian_completion: GuardianCompletion,
    identities: Vec<ToolProbeIdentity>,
}

impl SupervisorAuthorityDescriptors {
    fn create(scratch: &PackageScratch) -> Result<Self, Box<dyn Error>> {
        let registry = Registry::at(scratch.root.join("authority-registry"));
        let pending = registry.begin_codex_registration("package-authority")?;
        let synthetic_scope = Uuid::new_v4().to_string();
        // Registration needs only the account-scope shape used by the local
        // identity binder. No access token, refresh token, or provider URL is
        // present, and the official App below uses a different CODEX_HOME.
        let synthetic_auth = serde_json::to_vec(&json!({
            "auth_mode": "chatgpt",
            "tokens": { "account_id": synthetic_scope }
        }))?;
        write_private_new(&pending.home().join("auth.json"), &synthetic_auth)?;
        let profile = pending.commit(CodexIdentityAdapter::for_test())?;

        // These two calls are the production split-lease admission path: A is
        // held first, then B is admitted only after observing that exact live
        // coordinator lease and refetching the immutable profile row.
        let coordinator_lease = registry.lock_profile_coordinator(&profile)?;
        let guardian_lease = registry.lock_profile_guardian_current(&profile)?;
        let (lifecycle_coordinator, lifecycle_guardian) = LifecyclePair::new()?.split_for_test();
        let (terminal_coordinator, terminal_guardian) = TerminalChannelPair::new()?.split();
        let (anchor_completion, completion_transit) = CompletionPair::new()?.split();

        let mut identities = Vec::with_capacity(SUPERVISOR_AUTHORITY_DESCRIPTOR_COUNT);
        identities.push(tool_probe_identity_from_fd(
            coordinator_lease.lock_file()?.as_fd(),
        )?);
        identities.push(tool_probe_identity(
            guardian_lease.descriptor_identity_for_test()?,
        )?);
        identities.push(tool_probe_identity_from_fd(lifecycle_coordinator.as_fd())?);
        identities.push(tool_probe_identity_from_fd(lifecycle_guardian.as_fd())?);
        identities.push(tool_probe_identity_from_fd(terminal_coordinator.as_fd())?);
        identities.push(tool_probe_identity_from_fd(terminal_guardian.as_fd())?);
        identities.push(tool_probe_identity_from_fd(anchor_completion.as_fd())?);
        identities.push(tool_probe_identity_from_fd(completion_transit.as_fd())?);
        if identities.len() != SUPERVISOR_AUTHORITY_DESCRIPTOR_COUNT
            || identities
                .iter()
                .enumerate()
                .any(|(index, identity)| identities[..index].contains(identity))
        {
            return Err("supervisor authority descriptor identities were not unique".into());
        }

        let authorities = Self {
            coordinator_lease,
            guardian_lease,
            lifecycle_coordinator,
            lifecycle_guardian,
            terminal_coordinator,
            terminal_guardian,
            anchor_completion,
            guardian_completion: completion_transit.into_guardian(),
            identities,
        };
        let forbidden = authorities.cross_process_set()?;
        if forbidden.len() != SUPERVISOR_AUTHORITY_DESCRIPTOR_COUNT {
            return Err("supervisor authority descriptor set was incomplete".into());
        }
        drop(forbidden);
        Ok(authorities)
    }

    fn cross_process_set(
        &self,
    ) -> Result<calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>, Box<dyn Error>> {
        let mut set = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        self.coordinator_lease
            .append_forbidden_descriptor(&mut set)?;
        self.guardian_lease.append_forbidden_descriptor(&mut set)?;
        set.capture(self.lifecycle_coordinator.as_fd())?;
        set.capture(self.lifecycle_guardian.as_fd())?;
        self.terminal_coordinator
            .append_forbidden_descriptor(&mut set)?;
        self.terminal_guardian
            .append_forbidden_descriptor(&mut set)?;
        set.capture(self.anchor_completion.as_fd())?;
        self.guardian_completion
            .append_forbidden_descriptor(&mut set)?;
        if set.len() != SUPERVISOR_AUTHORITY_DESCRIPTOR_COUNT {
            return Err("supervisor authority descriptor set was incomplete".into());
        }
        Ok(set)
    }
}

fn tool_probe_identity_from_fd(
    descriptor: std::os::fd::BorrowedFd<'_>,
) -> Result<ToolProbeIdentity, Box<dyn Error>> {
    tool_probe_identity(calcifer_unix_child_fd::descriptor_identity(descriptor)?)
}

fn tool_probe_identity(
    identity: calcifer_unix_child_fd::DescriptorIdentity,
) -> Result<ToolProbeIdentity, Box<dyn Error>> {
    if identity.inode == 0 {
        return Err("supervisor authority descriptor identity was invalid".into());
    }
    Ok(ToolProbeIdentity {
        device: identity.device,
        inode: identity.inode,
    })
}

struct ToolLifetimeProbe {
    path: PathBuf,
    file: File,
}

impl ToolLifetimeProbe {
    fn create(path: &Path) -> Result<Self, Box<dyn Error>> {
        write_private_new(path, b"")?;
        Ok(Self {
            path: path.to_path_buf(),
            file: open_existing_private_file(path)?,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn assert_held_by_reported_tool(&self) -> Result<(), Box<dyn Error>> {
        match FileExt::try_lock_exclusive(&self.file) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Ok(()) => {
                FileExt::unlock(&self.file)?;
                Err("reported detached tool held no process-lifetime witness".into())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn wait_until_released(&self, deadline: Instant) -> Result<(), Box<dyn Error>> {
        loop {
            match FileExt::try_lock_exclusive(&self.file) {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err("detached tool process-lifetime witness did not release".into());
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn open_existing_private_file(path: &Path) -> Result<File, Box<dyn Error>> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("tool probe private file identity was invalid".into());
    }
    Ok(file)
}

fn assert_reported_tool_is_live(report: &ToolProbeReport) -> Result<(), Box<dyn Error>> {
    match observe_process_job_identity(report.pid)? {
        Some((process_group, session))
            if process_group == report.process_group && session == report.session =>
        {
            Ok(())
        }
        _ => Err("reported detached tool process identity was not live".into()),
    }
}

fn wait_for_reported_tool_pid_gone(
    report: &ToolProbeReport,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    loop {
        match observe_process_job_identity(report.pid)? {
            None => return Ok(()),
            Some((process_group, session))
                if process_group != report.process_group || session != report.session =>
            {
                return Err("detached tool PID was reused before absence was observed".into());
            }
            Some(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Some(_) => return Err("detached tool PID remained after process exit".into()),
        }
    }
}

fn observe_process_job_identity(pid: i32) -> Result<Option<(i32, i32)>, Box<dyn Error>> {
    let pid = rustix::process::Pid::from_raw(pid).ok_or("detached tool PID was invalid")?;
    let process_group = match rustix::process::getpgid(Some(pid)) {
        Ok(process_group) => process_group,
        Err(rustix::io::Errno::SRCH) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let session = match rustix::process::getsid(Some(pid)) {
        Ok(session) => session,
        Err(rustix::io::Errno::SRCH) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(Some((process_group.as_raw_pid(), session.as_raw_pid())))
}

fn start_running_turn(
    socket_path: &Path,
    scratch: &PackageScratch,
    provider: &DelayedProvider,
) -> Result<PackageAppWebSocket, Box<dyn Error>> {
    let mut client = connect_app_server(socket_path, Instant::now() + IO_TIMEOUT)?;

    send_request(
        &mut client,
        1,
        "initialize",
        json!({
            "clientInfo": {
                // Match the production identity adapter so this test exercises
                // the same version/home gate instead of minting a test-only
                // user-agent namespace.
                "name": "calcifer",
                "title": "Calcifer package smoke",
                "version": env!("CARGO_PKG_VERSION")
            },
            "capabilities": { "experimentalApi": false }
        }),
    )?;
    let initialize = receive_result(&mut client, 1, Instant::now() + IO_TIMEOUT)?;
    require_pinned_initialize(&initialize, &scratch.codex_home)?;

    send_request(
        &mut client,
        2,
        "thread/start",
        json!({
            "cwd": scratch.workspace,
            "model": "calcifer-package-smoke",
            "modelProvider": "calcifer_package_smoke",
            "approvalPolicy": "never",
            "sandbox": "read-only",
            "ephemeral": true
        }),
    )?;
    let started = receive_result(&mut client, 2, Instant::now() + IO_TIMEOUT)?;
    let thread_id = bounded_thread_id(&started)?;

    send_request(
        &mut client,
        3,
        "turn/start",
        json!({
            "threadId": thread_id,
            "input": [{ "type": "text", "text": "package smoke", "text_elements": [] }]
        }),
    )?;
    let _ = receive_result(&mut client, 3, Instant::now() + IO_TIMEOUT)?;
    provider.wait_for_request(Instant::now() + IO_TIMEOUT)?;
    Ok(client)
}

fn cleanup_setup_failure(
    app: ManagedGroupChild,
    provider: DelayedProvider,
    scratch: PackageScratch,
    original: Box<dyn Error>,
) -> Result<(), Box<dyn Error>> {
    let _ = provider.cancel_and_join();
    match shutdown_app_server_child(app, PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
        Ok(_) => {
            scratch.cleanup()?;
            Err(original)
        }
        Err(mut unreaped) => unreaped.park(),
    }
}

fn finish_unexpected_early_drain(
    result: Result<super::process::PinnedAppGracefulDrain, Box<super::process::UnreapedChildren>>,
    scratch: PackageScratch,
) -> Result<(), Box<dyn Error>> {
    match result {
        Ok(_) => {
            scratch.cleanup()?;
            Err("App Server exited before its running turn drained".into())
        }
        Err(mut unreaped) => match unreaped.retry_app_server(PROCESS_TIMEOUT, PROCESS_TIMEOUT) {
            Ok(_) => {
                scratch.cleanup()?;
                Err("App Server graceful drain failed before provider release".into())
            }
            Err(_) => unreaped.park(),
        },
    }
}

fn package_binary() -> Result<PathBuf, Box<dyn Error>> {
    let path = std::env::var_os(PACKAGE_BINARY_ENV)
        .map(PathBuf::from)
        .ok_or("CALCIFER_CODEX_COMPAT_BINARY must name the pinned Codex binary")?;
    let canonical = fs::canonicalize(&path)?;
    if canonical != path || !canonical.is_absolute() {
        return Err("the pinned Codex binary path must be absolute and canonical".into());
    }
    let metadata = fs::symlink_metadata(&canonical)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o6022 != 0
    {
        return Err("the pinned Codex binary identity is unsafe".into());
    }
    let output = Command::new(&canonical)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout != b"codex-cli 0.144.4\n" {
        return Err("the package is not the pinned Codex 0.144.4 build".into());
    }
    Ok(canonical)
}

fn package_provider_executable(
    target: PackageProviderTarget,
    root: &Path,
) -> Result<PathBuf, Box<dyn Error>> {
    match target {
        PackageProviderTarget::Official => package_binary(),
        PackageProviderTarget::DeterministicFixture => {
            let path = std::env::var_os(PACKAGE_BINARY_ENV)
                .map(PathBuf::from)
                .ok_or("deterministic package provider executable was missing")?;
            let canonical = fs::canonicalize(&path)?;
            let expected = root.join(PACKAGE_LIBTEST_PROVIDER_WRAPPER);
            let metadata = fs::symlink_metadata(&canonical)?;
            if path != canonical
                || canonical != expected
                || canonical.parent() != Some(root)
                || !metadata.file_type().is_file()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o7777 != 0o700
                || metadata.nlink() != 1
                || metadata.len() == 0
            {
                return Err("deterministic package provider executable was unsafe".into());
            }
            Ok(canonical)
        }
    }
}

fn validate_package_launcher_for_target(
    target: PackageProviderTarget,
    root: &Path,
    candidate: &Path,
) -> Result<PathBuf, Box<dyn Error>> {
    if target == PackageProviderTarget::Official {
        return Ok(candidate.to_path_buf());
    }
    let canonical = fs::canonicalize(candidate)?;
    let expected = root.join(PACKAGE_LIBTEST_LAUNCHER_WRAPPER);
    let metadata = fs::symlink_metadata(&canonical)?;
    if candidate != canonical
        || canonical != expected
        || canonical.parent() != Some(root)
        || !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() != 1
        || metadata.len() == 0
    {
        return Err("deterministic package launcher escaped its exact root binding".into());
    }
    Ok(canonical)
}

fn packaged_app_command(
    executable: &Path,
    scratch: &PackageScratch,
    socket_path: &Path,
) -> Command {
    let mut command = managed_command(executable, &scratch.codex_home);
    for name in MANAGED_ENVIRONMENT_DENYLIST {
        command.env(name, "must-not-reach-provider");
    }
    // Re-run the production sanitizer after installing deterministic poison;
    // this avoids mutating the multithreaded test process's global environment.
    sanitize_managed_environment(&mut command);
    command
        .args(["app-server", "--listen"])
        .arg(format!("unix://{}", socket_path.display()))
        .current_dir(&scratch.workspace)
        .env("HOME", &scratch.environment_home)
        .env("XDG_CONFIG_HOME", scratch.environment_home.join("config"))
        .env("XDG_DATA_HOME", scratch.environment_home.join("data"))
        .env("XDG_CACHE_HOME", scratch.environment_home.join("cache"))
        .env("XDG_RUNTIME_DIR", scratch.environment_home.join("run"))
        .env("TMPDIR", scratch.environment_home.join("tmp"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn write_test_config(
    codex_home: &Path,
    provider: std::net::SocketAddr,
) -> Result<(), Box<dyn Error>> {
    // A seeded rollout makes Codex 0.144.4 run its personality migration.
    // Pin the official default so that migration is a no-op and any other
    // post-launch config mutation still fails the exact contract check.
    let config = format!(
        r#"model = "calcifer-package-smoke"
model_provider = "{PACKAGE_SUPERVISOR_MODEL_PROVIDER}"
personality = "pragmatic"
approval_policy = "never"
sandbox_mode = "read-only"
cli_auth_credentials_store = "file"
mcp_oauth_credentials_store = "file"
check_for_update_on_startup = false

[analytics]
enabled = false

[otel]
exporter = "none"
trace_exporter = "none"
metrics_exporter = "none"

[tui]
show_tooltips = false

[features]
shell_snapshot = false
apps = false
plugins = false
remote_plugin = false

[model_providers.{PACKAGE_SUPERVISOR_MODEL_PROVIDER}]
name = "Calcifer package smoke"
base_url = "http://{provider}/v1"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
supports_websockets = false
requires_openai_auth = false
"#,
    );
    write_private_new(&codex_home.join("config.toml"), config.as_bytes())
}

fn write_usage_test_profile(
    codex_home: &Path,
    backend: std::net::SocketAddr,
) -> Result<(), Box<dyn Error>> {
    // This synthetic auth shape follows the official 0.144.4 App Server test
    // fixture. It is never admitted by Calcifer's production profile writer,
    // never leaves this mode-0700 scratch root, and can reach only the private
    // loopback backend installed below.
    write_private_new(&codex_home.join("auth.json"), &package_test_auth()?)?;
    write_private_new(
        &codex_home.join("config.toml"),
        package_usage_config(backend).as_bytes(),
    )
}

fn package_test_auth() -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(serde_json::to_vec(&json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": PACKAGE_FAKE_ID_TOKEN,
            "access_token": PACKAGE_FAKE_ACCESS_TOKEN,
            "refresh_token": "calcifer-package-refresh",
            "account_id": PACKAGE_FAKE_ACCOUNT_ID
        },
        "last_refresh": "2099-01-01T00:00:00Z"
    }))?)
}

fn package_usage_config(backend: std::net::SocketAddr) -> String {
    // Keep this in lockstep with `write_test_config`: this profile also owns a
    // seeded rollout and must enter the official migration already normalized.
    format!(
        r#"model = "calcifer-package-smoke"
model_provider = "{PACKAGE_SUPERVISOR_MODEL_PROVIDER}"
personality = "pragmatic"
approval_policy = "never"
sandbox_mode = "read-only"
cli_auth_credentials_store = "file"
mcp_oauth_credentials_store = "file"
chatgpt_base_url = "http://{backend}"
check_for_update_on_startup = false

[analytics]
enabled = false

[otel]
exporter = "none"
trace_exporter = "none"
metrics_exporter = "none"

[tui]
show_tooltips = false

[features]
shell_snapshot = false
apps = false
plugins = false
remote_plugin = false

[model_providers.{PACKAGE_SUPERVISOR_MODEL_PROVIDER}]
name = "Calcifer package smoke"
base_url = "http://{backend}/v1"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
supports_websockets = false
requires_openai_auth = false
"#,
    )
}

fn write_package_registration_auth(codex_home: &Path) -> Result<(), Box<dyn Error>> {
    write_private_new(&codex_home.join("auth.json"), &package_test_auth()?)
}

fn replace_package_profile_config(
    codex_home: &Path,
    backend: std::net::SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let temporary = codex_home.join("config.toml.package-pending");
    let destination = codex_home.join("config.toml");
    write_private_new(&temporary, package_usage_config(backend).as_bytes())?;
    fs::rename(&temporary, &destination)?;
    File::open(codex_home)?.sync_all()?;
    let metadata = fs::symlink_metadata(&destination)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("package profile config replacement was not private".into());
    }
    Ok(())
}

fn connect_app_server(
    socket_path: &Path,
    deadline: Instant,
) -> Result<PackageAppWebSocket, Box<dyn Error>> {
    loop {
        match UnixStream::connect(socket_path) {
            Ok(stream) => {
                stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
                let config = WebSocketConfig::default()
                    .max_message_size(Some(MAX_WEBSOCKET_MESSAGE_BYTES))
                    .max_frame_size(Some(MAX_WEBSOCKET_MESSAGE_BYTES));
                let (websocket, _) = client_with_config(
                    "ws://localhost/rpc",
                    ToolRequestWriteObserver::new(stream),
                    Some(config),
                )?;
                return Ok(websocket);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err("official App Server socket did not become ready".into());
        }
    }
}

fn send_request<S: Read + Write>(
    websocket: &mut WebSocket<S>,
    id: u64,
    method: &str,
    params: Value,
) -> Result<(), Box<dyn Error>> {
    let encoded = serde_json::to_string(&json!({
        "id": id,
        "method": method,
        "params": params
    }))?;
    if encoded.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
        return Err("package smoke request exceeded its bound".into());
    }
    websocket.send(Message::text(encoded))?;
    Ok(())
}

fn receive_result<S: Read + Write>(
    websocket: &mut WebSocket<S>,
    expected_id: u64,
    deadline: Instant,
) -> Result<Value, Box<dyn Error>> {
    loop {
        if Instant::now() >= deadline {
            return Err("package smoke response exceeded its deadline".into());
        }
        match websocket.read() {
            Ok(Message::Text(text)) => {
                if text.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
                    return Err("package smoke response exceeded its bound".into());
                }
                let value: Value = serde_json::from_str(&text)?;
                if value.get("id").and_then(Value::as_u64) != Some(expected_id) {
                    continue;
                }
                if value.get("error").is_some() {
                    return Err("official App Server returned a redacted protocol error".into());
                }
                return value
                    .get("result")
                    .cloned()
                    .ok_or_else(|| "official App Server response had no result".into());
            }
            Ok(Message::Ping(bytes)) => websocket.send(Message::Pong(bytes))?,
            Ok(Message::Close(_)) => return Err("official App Server disconnected".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn require_pinned_initialize(result: &Value, expected_home: &Path) -> Result<(), Box<dyn Error>> {
    if validate_initialize_result(result.clone(), expected_home)
        .map_err(|_| "official App Server initialize contract drifted")?
        != "0.144.4"
    {
        return Err("official App Server initialize version drifted".into());
    }
    Ok(())
}

fn bounded_thread_id(result: &Value) -> Result<String, Box<dyn Error>> {
    let id = result
        .pointer("/thread/id")
        .and_then(Value::as_str)
        .ok_or("thread/start omitted the thread id")?;
    if id.len() > 64 || Uuid::parse_str(id).is_err() {
        return Err("thread/start returned an invalid thread id".into());
    }
    Ok(id.to_owned())
}

struct PackageSessionBackend {
    address: std::net::SocketAddr,
    deadline: Instant,
    cancel: Option<SyncSender<()>>,
    inference_completed: Receiver<()>,
    worker: Option<JoinHandle<Result<PackageSessionBackendObservation, String>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageSessionBackendTransportFailure {
    marker: &'static str,
}

impl fmt::Display for PackageSessionBackendTransportFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the package session backend transport failed")
    }
}

impl Error for PackageSessionBackendTransportFailure {}

const PACKAGE_SESSION_BACKEND_FAILURE_CLASSIFICATIONS: &[(&str, &str)] = &[
    (
        "package session backend nonblocking setup failed",
        "package-backend.lifecycle.nonblocking",
    ),
    (
        "package session backend cancellation authority disappeared",
        "package-backend.lifecycle.cancel-disconnected",
    ),
    (
        "package session backend exceeded its lifetime bound",
        "package-backend.lifecycle.deadline",
    ),
    (
        "package session backend accept failed",
        "package-backend.listener.accept",
    ),
    (
        "package session backend received too many requests",
        "package-backend.listener.request-limit",
    ),
    (
        "package session backend blocking setup failed",
        "package-backend.stream.blocking",
    ),
    (
        "package session backend read timeout setup failed",
        "package-backend.stream.read-timeout",
    ),
    (
        "package session backend write timeout setup failed",
        "package-backend.stream.write-timeout",
    ),
    (
        "rate-limit backend request read failed",
        "package-backend.request.read",
    ),
    (
        "rate-limit backend request ended early",
        "package-backend.request.eof",
    ),
    (
        "rate-limit backend request exceeded its bound",
        "package-backend.request.size",
    ),
    (
        "rate-limit backend headers were invalid",
        "package-backend.request.headers",
    ),
    (
        "rate-limit backend received an invalid request line",
        "package-backend.request.line",
    ),
    (
        "rate-limit backend received a malformed header",
        "package-backend.request.header-malformed",
    ),
    (
        "rate-limit backend received duplicate authorization headers",
        "package-backend.request.authorization-duplicate",
    ),
    (
        "rate-limit backend received duplicate account headers",
        "package-backend.request.account-duplicate",
    ),
    (
        "rate-limit backend received duplicate body lengths",
        "package-backend.request.content-length-duplicate",
    ),
    (
        "rate-limit backend received duplicate content types",
        "package-backend.request.content-type-duplicate",
    ),
    (
        "rate-limit backend received duplicate accept headers",
        "package-backend.request.accept-duplicate",
    ),
    (
        "package session backend received invalid credentials",
        "package-backend.request.credentials",
    ),
    (
        "package models request unexpectedly carried a body",
        "package-backend.models.body",
    ),
    (
        "package response request body was invalid JSON",
        "package-backend.response.invalid-json",
    ),
    (
        "package response request model did not match the pinned fixture",
        "package-backend.response.model",
    ),
    (
        "package response request was not streaming",
        "package-backend.response.stream",
    ),
    (
        "package response request omitted the fixed current prompt",
        "package-backend.response.prompt-missing",
    ),
    (
        "package response request duplicated the fixed current prompt",
        "package-backend.response.prompt-duplicate",
    ),
    (
        "package response request had invalid media headers",
        "package-backend.response.media",
    ),
    (
        "package response request had invalid credential headers",
        "package-backend.response.credentials",
    ),
    (
        "package response request used an unsupported body encoding",
        "package-backend.response.encoding",
    ),
    (
        "package response request omitted a bounded body length",
        "package-backend.response.content-length",
    ),
    (
        "package response request contained trailing bytes",
        "package-backend.response.trailing",
    ),
    (
        "package response request length overflowed",
        "package-backend.response.length-overflow",
    ),
    (
        "package response request body ended early",
        "package-backend.response.body-eof",
    ),
    (
        "rate-limit backend fixture serialization failed",
        "package-backend.response.usage-serialization",
    ),
    (
        "reset-credit backend fixture serialization failed",
        "package-backend.response.reset-serialization",
    ),
    (
        "rate-limit backend response failed",
        "package-backend.response.json-write",
    ),
    (
        "package response stream write failed",
        "package-backend.response.sse-write",
    ),
    (
        "package response stream EOF publication failed",
        "package-backend.response.sse-eof",
    ),
    (
        "package inference disconnect failed",
        "package-backend.response.disconnect",
    ),
    (
        "package session backend received duplicate responses calls",
        "package-backend.observation.duplicate-responses",
    ),
    (
        "package session backend inference completion authority failed",
        "package-backend.observation.completion-publish",
    ),
];

fn classify_package_session_backend_failure(error: &str) -> &'static str {
    PACKAGE_SESSION_BACKEND_FAILURE_CLASSIFICATIONS
        .iter()
        .find_map(|(known, marker)| (*known == error).then_some(*marker))
        .unwrap_or("package-backend.unclassified")
}

#[test]
fn package_session_backend_failure_classification_is_closed_and_payload_free() {
    for &(error, marker) in PACKAGE_SESSION_BACKEND_FAILURE_CLASSIFICATIONS {
        assert_eq!(classify_package_session_backend_failure(error), marker);
        assert!(PACKAGE_SESSION_BACKEND_FAILURE_MARKERS.contains(&marker));
        assert!(!marker.contains("private"));
    }
    assert_eq!(
        classify_package_session_backend_failure("private-provider-controlled-transport-detail"),
        "package-backend.unclassified"
    );
    let classified: BTreeSet<_> = PACKAGE_SESSION_BACKEND_FAILURE_CLASSIFICATIONS
        .iter()
        .map(|(_, marker)| *marker)
        .chain(["package-backend.unclassified"])
        .collect();
    let catalog: BTreeSet<_> = PACKAGE_SESSION_BACKEND_FAILURE_MARKERS
        .iter()
        .copied()
        .collect();
    assert_eq!(classified, catalog);
    assert_eq!(catalog.len(), PACKAGE_SESSION_BACKEND_FAILURE_MARKERS.len());
    assert!(catalog.iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("package-backend.")
            && marker.len() <= 96
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageInferenceResponseMode {
    Complete,
    DisconnectAfterValidatedRequest,
}

impl PackageSessionBackend {
    fn spawn() -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_response_mode(PackageInferenceResponseMode::Complete)
    }

    fn spawn_with_disconnected_inference() -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_response_mode(
            PackageInferenceResponseMode::DisconnectAfterValidatedRequest,
        )
    }

    fn spawn_with_response_mode(
        response_mode: PackageInferenceResponseMode,
    ) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let deadline = Instant::now()
            .checked_add(PACKAGE_SESSION_BACKEND_TIMEOUT)
            .ok_or("package session backend deadline overflowed")?;
        let (cancel, cancellation) = mpsc::sync_channel(1);
        let (inference_completion, inference_completed) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("calcifer-package-session-backend".to_owned())
            .spawn(move || {
                serve_package_session_backend(
                    listener,
                    cancellation,
                    inference_completion,
                    deadline,
                    response_mode,
                )
            })?;
        Ok(Self {
            address,
            deadline,
            cancel: Some(cancel),
            inference_completed,
            worker: Some(worker),
        })
    }

    const fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    const fn deadline(&self) -> Instant {
        self.deadline
    }

    fn wait_for_inference_completion(&self, deadline: Instant) -> Result<(), Box<dyn Error>> {
        self.inference_completed
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "package session backend did not complete validated inference".into())
    }

    fn cancel_and_join_transport(
        mut self,
    ) -> Result<PackageSessionBackendObservation, Box<dyn Error>> {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.try_send(());
        }
        let worker = self
            .worker
            .take()
            .ok_or("package session backend worker was already joined")?;
        let outcome = worker
            .join()
            .map_err(|_| "package session backend worker panicked")?;
        match outcome {
            Ok(observation) => Ok(observation),
            Err(error) => Err(Box::new(PackageSessionBackendTransportFailure {
                marker: classify_package_session_backend_failure(&error),
            })),
        }
    }

    fn cancel_join_and_require_inference_evidence(self) -> Result<(), Box<dyn Error>> {
        let observation = self.cancel_and_join_transport()?;
        // The official-package harness treats cleanup as part of success, so
        // this typed readback is the final inference-routing evidence rather
        // than an observation-only diagnostic.
        observation.require_exactly_one_responses_call()?;
        Ok(())
    }
}

impl Drop for PackageSessionBackend {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.try_send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn exchange_package_session_backend(
    address: std::net::SocketAddr,
    request: &[u8],
) -> Result<String, Box<dyn Error>> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(request)?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(std::str::from_utf8(&response)?.to_owned())
}

/// Negative-contract exchange only. Darwin may surface the server's deliberate
/// reject-and-close as `ECONNRESET` when unread request bytes remain. Treat
/// only that transport result as an empty rejection; positive-path callers
/// continue to require a complete HTTP response through the strict helper.
fn exchange_rejected_package_session_backend(
    address: std::net::SocketAddr,
    request: &[u8],
) -> Result<String, Box<dyn Error>> {
    match exchange_package_session_backend(address, request) {
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::ConnectionReset) =>
        {
            Ok(String::new())
        }
        result => result,
    }
}

fn package_responses_http_request(body: &[u8], extra_headers: &str) -> Vec<u8> {
    let headers = format!(
        "POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
        body.len()
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(body);
    request
}

fn package_response_credential_headers(access_token: &str, account_id: &str) -> String {
    format!("Authorization: Bearer {access_token}\r\nChatGPT-Account-Id: {account_id}\r\n")
}

fn valid_package_responses_body() -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(serde_json::to_vec(&json!({
        "model": PACKAGE_SUPERVISOR_MODEL,
        "stream": true,
        "input": [{
            "type": "message",
            "role": "user",
            "content": [{
                "type": "input_text",
                "text": PACKAGE_SUPERVISOR_INITIAL_PROMPT
            }]
        }]
    }))?)
}

fn valid_package_responses_request() -> Result<Vec<u8>, Box<dyn Error>> {
    let body = valid_package_responses_body()?;
    let credential_headers =
        package_response_credential_headers(PACKAGE_FAKE_ACCESS_TOKEN, PACKAGE_FAKE_ACCOUNT_ID);
    Ok(package_responses_http_request(&body, &credential_headers))
}

fn package_models_http_request(path_and_query: &str, access_token: &str) -> Vec<u8> {
    format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {access_token}\r\nChatGPT-Account-Id: {PACKAGE_FAKE_ACCOUNT_ID}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

#[test]
fn package_session_backend_serves_the_pinned_official_models_contract() -> Result<(), Box<dyn Error>>
{
    let backend = PackageSessionBackend::spawn()?;
    let models = exchange_package_session_backend(
        backend.address(),
        &package_models_http_request(
            "/v1/models?client_version=0.144.4",
            PACKAGE_FAKE_ACCESS_TOKEN,
        ),
    )?;
    assert!(models.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(models.contains("\r\n\r\n{\"models\":[]}"));
    assert!(!models.contains(PACKAGE_FAKE_ACCESS_TOKEN));

    let inference =
        exchange_package_session_backend(backend.address(), &valid_package_responses_request()?)?;
    assert!(inference.starts_with("HTTP/1.1 200 OK\r\n"));
    backend.cancel_join_and_require_inference_evidence()
}

#[test]
fn package_session_backend_rejects_models_contract_drift_and_credentials()
-> Result<(), Box<dyn Error>> {
    for path_and_query in [
        "/v1/models",
        "/v1/models?client_version=0.144.3",
        "/v1/models?client_version=0.144.4&client_version=0.144.4",
        "/v1/models?client_version=0.144.4&unexpected=true",
    ] {
        let backend = PackageSessionBackend::spawn()?;
        let response = exchange_rejected_package_session_backend(
            backend.address(),
            &package_models_http_request(path_and_query, PACKAGE_FAKE_ACCESS_TOKEN),
        )?;
        assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(!response.contains(PACKAGE_FAKE_ACCESS_TOKEN));
        backend
            .cancel_and_join_transport()?
            .require_zero_responses_calls()?;
    }

    let backend = PackageSessionBackend::spawn()?;
    let invalid_token = "calcifer-private-invalid-model-token";
    let response = exchange_rejected_package_session_backend(
        backend.address(),
        &package_models_http_request("/v1/models?client_version=0.144.4", invalid_token),
    )?;
    assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.contains(invalid_token));
    let error = require_rejected_test_result(
        backend.cancel_and_join_transport(),
        "an invalid models credential reached the response path",
    )?;
    assert!(!error.to_string().contains(invalid_token));

    let backend = PackageSessionBackend::spawn()?;
    let request = package_models_http_request(
        "/v1/models?client_version=0.144.4",
        PACKAGE_FAKE_ACCESS_TOKEN,
    );
    let request = std::str::from_utf8(&request)?.replacen("GET /v1/models", "POST /v1/models", 1);
    let response =
        exchange_rejected_package_session_backend(backend.address(), request.as_bytes())?;
    assert!(response.is_empty() || response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.contains(PACKAGE_FAKE_ACCESS_TOKEN));
    backend
        .cancel_and_join_transport()?
        .require_zero_responses_calls()?;
    Ok(())
}

#[test]
fn package_session_backend_serves_one_validated_responses_stream_for_the_official_tui()
-> Result<(), Box<dyn Error>> {
    let backend = PackageSessionBackend::spawn()?;
    let response =
        exchange_package_session_backend(backend.address(), &valid_package_responses_request()?)?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("Content-Type: text/event-stream\r\n"));
    assert!(response.contains("event: response.created\n"));
    assert!(response.contains("event: response.completed\n"));
    assert!(response.contains(PACKAGED_TUI_OUTPUT_SENTINEL));
    assert!(!response.contains(PACKAGE_SUPERVISOR_STARTUP_SENTINEL));
    assert!(!response.contains(PACKAGE_FAKE_ACCESS_TOKEN));

    let usage_request = format!(
        "GET /api/codex/usage HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {PACKAGE_FAKE_ACCESS_TOKEN}\r\nChatGPT-Account-Id: {PACKAGE_FAKE_ACCOUNT_ID}\r\nConnection: close\r\n\r\n"
    );
    let usage = exchange_package_session_backend(backend.address(), usage_request.as_bytes())?;
    assert!(usage.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(usage.contains("\"plan_type\":\"pro\""));
    assert!(!usage.contains(PACKAGE_FAKE_ACCESS_TOKEN));

    let reset_credit_request = format!(
        "GET /api/codex/rate-limit-reset-credits HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {PACKAGE_FAKE_ACCESS_TOKEN}\r\nChatGPT-Account-Id: {PACKAGE_FAKE_ACCOUNT_ID}\r\nConnection: close\r\n\r\n"
    );
    let reset_credits =
        exchange_package_session_backend(backend.address(), reset_credit_request.as_bytes())?;
    assert!(reset_credits.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(reset_credits.contains("\"available_count\":2"));
    assert!(!reset_credits.contains(PACKAGE_FAKE_ACCESS_TOKEN));
    backend.cancel_join_and_require_inference_evidence()?;
    Ok(())
}

#[test]
fn package_session_backend_keeps_listening_after_a_bounded_unknown_post()
-> Result<(), Box<dyn Error>> {
    let backend = PackageSessionBackend::spawn()?;
    let body = br#"{"private":"must-not-be-retained"}"#;
    let mut unknown = format!(
        "POST /api/codex/ps/mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    unknown.extend_from_slice(body);
    let response = exchange_rejected_package_session_backend(backend.address(), &unknown)?;
    assert!(response.is_empty() || response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.contains("must-not-be-retained"));

    let usage_request = format!(
        "GET /api/codex/usage HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {PACKAGE_FAKE_ACCESS_TOKEN}\r\nChatGPT-Account-Id: {PACKAGE_FAKE_ACCOUNT_ID}\r\nConnection: close\r\n\r\n"
    );
    let usage = exchange_package_session_backend(backend.address(), usage_request.as_bytes())?;
    assert!(usage.starts_with("HTTP/1.1 200 OK\r\n"));

    let inference =
        exchange_package_session_backend(backend.address(), &valid_package_responses_request()?)?;
    assert!(inference.starts_with("HTTP/1.1 200 OK\r\n"));
    backend.cancel_join_and_require_inference_evidence()
}

#[test]
fn package_session_backend_keeps_listening_after_an_unknown_chunked_request()
-> Result<(), Box<dyn Error>> {
    let backend = PackageSessionBackend::spawn()?;
    let unknown = b"POST /api/codex/ps/mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n7\r\nprivate\r\n0\r\n\r\n";
    let response = exchange_rejected_package_session_backend(backend.address(), unknown)?;
    assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.contains("private"));

    let usage_request = format!(
        "GET /api/codex/usage HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {PACKAGE_FAKE_ACCESS_TOKEN}\r\nChatGPT-Account-Id: {PACKAGE_FAKE_ACCOUNT_ID}\r\nConnection: close\r\n\r\n"
    );
    let usage = exchange_package_session_backend(backend.address(), usage_request.as_bytes())?;
    assert!(usage.starts_with("HTTP/1.1 200 OK\r\n"));

    let inference =
        exchange_package_session_backend(backend.address(), &valid_package_responses_request()?)?;
    assert!(inference.starts_with("HTTP/1.1 200 OK\r\n"));
    backend.cancel_join_and_require_inference_evidence()
}

#[test]
fn package_session_backend_rejects_unknown_headers_without_reading_private_bodies()
-> Result<(), Box<dyn Error>> {
    let backend = PackageSessionBackend::spawn()?;

    // The peer advertises a private body, sends only a prefix, and cancels.
    // Unknown traffic must be rejected from the bounded header alone; its
    // body is outside the fixture's authority and cannot kill the shared
    // usage/inference listener.
    let mut truncated = TcpStream::connect(backend.address())?;
    truncated.set_read_timeout(Some(IO_TIMEOUT))?;
    truncated.set_write_timeout(Some(IO_TIMEOUT))?;
    truncated.write_all(
        b"POST /api/codex/ps/mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4096\r\nConnection: close\r\n\r\nprivate",
    )?;
    truncated.shutdown(std::net::Shutdown::Write)?;
    let mut truncated_response = Vec::new();
    let truncated_read = truncated.read_to_end(&mut truncated_response);
    if let Err(error) = &truncated_read {
        if error.kind() != io::ErrorKind::ConnectionReset {
            return Err(error.to_string().into());
        }
    }
    assert!(!truncated_response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        !truncated_response
            .windows(7)
            .any(|bytes| bytes == b"private")
    );

    let duplicate_lengths = b"POST /api/codex/ps/mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 7\r\nContent-Length: 8\r\nConnection: close\r\n\r\nprivate";
    let duplicate_response =
        exchange_rejected_package_session_backend(backend.address(), duplicate_lengths)?;
    assert!(!duplicate_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!duplicate_response.contains("private"));

    let usage_request = format!(
        "GET /api/codex/usage HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {PACKAGE_FAKE_ACCESS_TOKEN}\r\nChatGPT-Account-Id: {PACKAGE_FAKE_ACCOUNT_ID}\r\nConnection: close\r\n\r\n"
    );
    let usage = exchange_package_session_backend(backend.address(), usage_request.as_bytes())?;
    assert!(usage.starts_with("HTTP/1.1 200 OK\r\n"));

    let inference =
        exchange_package_session_backend(backend.address(), &valid_package_responses_request()?)?;
    assert!(inference.starts_with("HTTP/1.1 200 OK\r\n"));
    backend.cancel_join_and_require_inference_evidence()
}

#[test]
fn package_unknown_response_write_failure_is_connection_local() {
    struct DisconnectedPeer;

    impl Write for DisconnectedPeer {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "synthetic disconnected peer",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "synthetic disconnected peer",
            ))
        }
    }

    write_unknown_package_response(&mut DisconnectedPeer);
}

#[test]
fn package_session_backend_acknowledges_a_completed_validated_response()
-> Result<(), Box<dyn Error>> {
    let backend = PackageSessionBackend::spawn()?;
    let response =
        exchange_package_session_backend(backend.address(), &valid_package_responses_request()?)?;
    assert!(response.contains("event: response.completed\n"));
    backend.wait_for_inference_completion(Instant::now() + IO_TIMEOUT)?;
    backend.cancel_join_and_require_inference_evidence()
}

#[test]
fn package_inference_completion_is_published_only_after_http_write_eof()
-> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (completion_sender, completion_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|_| "package EOF regression accept failed".to_owned())?;
        write_responses_http_response_and_publish(&mut stream, &completion_sender)?;
        release_receiver
            .recv_timeout(IO_TIMEOUT)
            .map_err(|_| "package EOF regression release disappeared".to_owned())?;
        Ok(())
    });

    let mut client = TcpStream::connect(address)?;
    client.set_read_timeout(Some(Duration::from_secs(1)))?;
    completion_receiver.recv_timeout(IO_TIMEOUT)?;
    let mut response = Vec::new();
    let read = client.read_to_end(&mut response);
    let _ = release_sender.try_send(());
    server
        .join()
        .map_err(|_| "package EOF regression server panicked")?
        .map_err(|error| -> Box<dyn Error> { error.into() })?;
    read?;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(package_responses_sse_body().as_bytes()));
    Ok(())
}

#[test]
fn package_session_backend_rejects_unexpected_responses_shape_and_invalid_auth_headers()
-> Result<(), Box<dyn Error>> {
    let valid_credentials =
        package_response_credential_headers(PACKAGE_FAKE_ACCESS_TOKEN, PACKAGE_FAKE_ACCOUNT_ID);
    let invalid_bodies = [
        json!({ "model": "unexpected-model", "stream": true }),
        json!({ "model": "calcifer-package-smoke", "stream": false }),
        json!({ "model": "calcifer-package-smoke" }),
        json!({
            "model": "calcifer-package-smoke",
            "stream": true,
            "input": [{
                "type": "message",
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": "unrelated-private-prompt"
                }]
            }]
        }),
    ];
    for body in invalid_bodies {
        let backend = PackageSessionBackend::spawn()?;
        let body = serde_json::to_vec(&body)?;
        let response = exchange_rejected_package_session_backend(
            backend.address(),
            &package_responses_http_request(&body, &valid_credentials),
        )?;
        assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(
            backend
                .cancel_join_and_require_inference_evidence()
                .is_err()
        );
    }

    let valid_body = valid_package_responses_body()?;
    for credential_headers in [
        String::new(),
        package_response_credential_headers("must-not-reach-provider", PACKAGE_FAKE_ACCOUNT_ID),
        package_response_credential_headers(PACKAGE_FAKE_ACCESS_TOKEN, "wrong-account"),
        format!(
            "{}Authorization: Bearer duplicate-private-token\r\n",
            valid_credentials
        ),
    ] {
        let backend = PackageSessionBackend::spawn()?;
        let request = package_responses_http_request(&valid_body, &credential_headers);
        let response = exchange_rejected_package_session_backend(backend.address(), &request)?;
        assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
        let error = match backend.cancel_join_and_require_inference_evidence() {
            Ok(()) => return Err("invalid response credentials were accepted".into()),
            Err(error) => error.to_string(),
        };
        for private in [
            "must-not-reach-provider",
            "wrong-account",
            "duplicate-private-token",
            PACKAGE_FAKE_ACCESS_TOKEN,
        ] {
            assert!(!error.contains(private));
        }
    }

    let backend = PackageSessionBackend::spawn()?;
    let request = valid_package_responses_request()?;
    let request =
        std::str::from_utf8(&request)?.replacen("Content-Type: application/json\r\n", "", 1);
    let response =
        exchange_rejected_package_session_backend(backend.address(), request.as_bytes())?;
    assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(
        backend
            .cancel_join_and_require_inference_evidence()
            .is_err()
    );
    Ok(())
}

#[test]
fn package_session_backend_requires_exactly_one_validated_responses_call()
-> Result<(), Box<dyn Error>> {
    let backend = PackageSessionBackend::spawn()?;
    assert!(
        backend
            .cancel_join_and_require_inference_evidence()
            .is_err()
    );

    let backend = PackageSessionBackend::spawn()?;
    let request = valid_package_responses_request()?;
    let first = exchange_package_session_backend(backend.address(), &request)?;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    let second = exchange_rejected_package_session_backend(backend.address(), &request)?;
    assert!(!second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(
        backend
            .cancel_join_and_require_inference_evidence()
            .is_err()
    );
    Ok(())
}

fn package_session_backend_cancellation_requested(
    cancellation: &Receiver<()>,
) -> Result<bool, String> {
    match cancellation.try_recv() {
        Ok(()) => Ok(true),
        Err(mpsc::TryRecvError::Empty) => Ok(false),
        Err(mpsc::TryRecvError::Disconnected) => {
            Err("package session backend cancellation authority disappeared".to_owned())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageBackendStreamSetupFailure {
    Blocking,
    ReadTimeout,
    WriteTimeout,
}

fn configure_package_backend_stream(
    stream: &TcpStream,
) -> Result<(), PackageBackendStreamSetupFailure> {
    stream
        .set_nonblocking(false)
        .map_err(|_| PackageBackendStreamSetupFailure::Blocking)?;
    stream
        .set_read_timeout(Some(PACKAGE_BACKEND_READ_SLICE))
        .map_err(|_| PackageBackendStreamSetupFailure::ReadTimeout)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| PackageBackendStreamSetupFailure::WriteTimeout)
}

const fn package_session_backend_stream_setup_error(
    failure: PackageBackendStreamSetupFailure,
) -> &'static str {
    match failure {
        PackageBackendStreamSetupFailure::Blocking => {
            "package session backend blocking setup failed"
        }
        PackageBackendStreamSetupFailure::ReadTimeout => {
            "package session backend read timeout setup failed"
        }
        PackageBackendStreamSetupFailure::WriteTimeout => {
            "package session backend write timeout setup failed"
        }
    }
}

#[test]
fn package_session_backend_cancellation_is_closed_and_prioritized() -> Result<(), Box<dyn Error>> {
    let (cancel, cancellation) = mpsc::sync_channel(1);
    assert_eq!(
        package_session_backend_cancellation_requested(&cancellation),
        Ok(false)
    );
    cancel.try_send(())?;
    assert_eq!(
        package_session_backend_cancellation_requested(&cancellation),
        Ok(true)
    );

    let (cancel, cancellation) = mpsc::sync_channel(1);
    drop(cancel);
    let error = require_rejected_test_result(
        package_session_backend_cancellation_requested(&cancellation),
        "a disconnected cancellation authority was accepted",
    )?;
    assert_eq!(
        classify_package_session_backend_failure(&error),
        "package-backend.lifecycle.cancel-disconnected"
    );
    Ok(())
}

#[test]
fn package_backend_accepted_stream_is_explicitly_blocking_and_bounded() -> Result<(), Box<dyn Error>>
{
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let _client = TcpStream::connect(listener.local_addr()?)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    };

    configure_package_backend_stream(&stream)
        .map_err(|_| "synthetic accepted stream setup failed")?;
    assert!(!rustix::fs::fcntl_getfl(&stream)?.contains(rustix::fs::OFlags::NONBLOCK));
    assert_eq!(stream.read_timeout()?, Some(PACKAGE_BACKEND_READ_SLICE));
    assert_eq!(stream.write_timeout()?, Some(IO_TIMEOUT));
    Ok(())
}

#[test]
fn package_backend_empty_connected_peer_is_connection_local() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let (_cancel, cancellation) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || -> Result<PackageBackendReadOutcome, String> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|_| "synthetic idle-peer accept failed".to_owned())?;
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|_| "synthetic idle-peer timeout setup failed".to_owned())?;
        read_rate_limit_request(&mut stream, &cancellation)
    });
    let _idle = TcpStream::connect(address)?;
    let result = worker
        .join()
        .map_err(|_| "synthetic idle-peer worker panicked")?;
    assert_eq!(
        result,
        Ok(PackageBackendReadOutcome::AbandonedBeforeRequest),
        "an empty connected peer was not isolated from the shared package backend"
    );
    Ok(())
}

#[test]
fn package_session_backend_idle_peer_does_not_head_of_line_block_usage()
-> Result<(), Box<dyn Error>> {
    let backend = PackageSessionBackend::spawn()?;
    let idle = TcpStream::connect(backend.address())?;
    // Let the single authoritative listener accept the idle peer before the
    // real request is enqueued behind it.
    thread::sleep(Duration::from_millis(50));

    let address = backend.address();
    let (published, observed) = mpsc::sync_channel(1);
    let client = thread::spawn(move || {
        let request = format!(
            "GET /api/codex/usage HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {PACKAGE_FAKE_ACCESS_TOKEN}\r\nChatGPT-Account-Id: {PACKAGE_FAKE_ACCOUNT_ID}\r\nConnection: close\r\n\r\n"
        );
        let result = exchange_package_session_backend(address, request.as_bytes())
            .map_err(|_| "authoritative usage exchange failed".to_owned());
        let _ = published.try_send(result);
    });
    let response = observed.recv_timeout(Duration::from_secs(3));
    drop(idle);
    client
        .join()
        .map_err(|_| "authoritative usage client panicked")?;
    let response = match response {
        Ok(response) => response.map_err(|error| -> Box<dyn Error> { error.into() })?,
        Err(_) => {
            let _ = backend.cancel_and_join_transport();
            return Err("an idle peer blocked the authoritative usage request".into());
        }
    };
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

    let inference = exchange_package_session_backend(address, &valid_package_responses_request()?)?;
    assert!(inference.starts_with("HTTP/1.1 200 OK\r\n"));
    backend.cancel_join_and_require_inference_evidence()
}

#[test]
fn package_session_backend_accepts_a_request_split_across_read_slices() -> Result<(), Box<dyn Error>>
{
    let backend = PackageSessionBackend::spawn()?;
    let mut client = TcpStream::connect(backend.address())?;
    client.set_read_timeout(Some(IO_TIMEOUT))?;
    client.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = format!(
        "GET /api/codex/usage HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {PACKAGE_FAKE_ACCESS_TOKEN}\r\nChatGPT-Account-Id: {PACKAGE_FAKE_ACCOUNT_ID}\r\nConnection: close\r\n\r\n"
    );
    let split = request.len() / 2;
    client.write_all(&request.as_bytes()[..split])?;
    client.flush()?;
    thread::sleep(PACKAGE_BACKEND_READ_SLICE + Duration::from_millis(50));
    client.write_all(&request.as_bytes()[split..])?;
    client.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

    let inference =
        exchange_package_session_backend(backend.address(), &valid_package_responses_request()?)?;
    assert!(inference.starts_with("HTTP/1.1 200 OK\r\n"));
    backend.cancel_join_and_require_inference_evidence()
}

#[test]
fn package_session_backend_cleanup_wins_over_an_accepted_partial_request()
-> Result<(), Box<dyn Error>> {
    let backend = PackageSessionBackend::spawn()?;
    let mut partial = TcpStream::connect(backend.address())?;
    partial.write_all(b"GET /api/codex/usage HTTP/1.1\r\nHost: ")?;
    partial.flush()?;
    thread::sleep(Duration::from_millis(50));

    let started = Instant::now();
    let observation = backend.cancel_and_join_transport()?;
    assert!(started.elapsed() < Duration::from_secs(3));
    observation.require_zero_responses_calls()?;
    drop(partial);
    Ok(())
}

fn serve_package_session_backend(
    listener: TcpListener,
    cancellation: Receiver<()>,
    inference_completion: SyncSender<()>,
    deadline: Instant,
    response_mode: PackageInferenceResponseMode,
) -> Result<PackageSessionBackendObservation, String> {
    listener
        .set_nonblocking(true)
        .map_err(|_| "package session backend nonblocking setup failed".to_owned())?;
    let mut requests = 0_usize;
    let mut observation = PackageSessionBackendObservation::default();
    loop {
        if package_session_backend_cancellation_requested(&cancellation)? {
            return Ok(observation);
        }
        if Instant::now() >= deadline {
            return Err("package session backend exceeded its lifetime bound".to_owned());
        }
        let (mut stream, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(_) => return Err("package session backend accept failed".to_owned()),
        };
        // Cancellation can race the nonblocking poll and the following
        // accept. Re-check before counting or parsing the accepted peer so
        // cleanup wins over one additional request at that boundary.
        if package_session_backend_cancellation_requested(&cancellation)? {
            return Ok(observation);
        }
        configure_package_backend_stream(&stream)
            .map_err(package_session_backend_stream_setup_error)
            .map_err(str::to_owned)?;
        requests = requests.saturating_add(1);
        if requests > 64 {
            return Err("package session backend received too many requests".to_owned());
        }
        let request = match read_rate_limit_request(&mut stream, &cancellation) {
            Ok(PackageBackendReadOutcome::Request(request)) => request,
            Ok(PackageBackendReadOutcome::AbandonedBeforeRequest) => continue,
            Ok(PackageBackendReadOutcome::Cancelled) => return Ok(observation),
            Err(error) => {
                // Once cleanup owns cancellation, a peer that was already
                // accepted may disappear or stop mid-request. Cancellation
                // wins only at that explicit boundary; the same partial read
                // remains fatal while the backend is serving a live session.
                if package_session_backend_cancellation_requested(&cancellation)? {
                    return Ok(observation);
                }
                return Err(error);
            }
        };
        if package_session_backend_cancellation_requested(&cancellation)? {
            return Ok(observation);
        }
        match request {
            PackageBackendRequest::Usage {
                credential_headers_match: true,
            } => {
                write_json_http_response(&mut stream, "200 OK", &usage_backend_body()?)?;
            }
            PackageBackendRequest::ResetCredits {
                credential_headers_match: true,
            } => {
                write_json_http_response(&mut stream, "200 OK", &reset_credit_backend_body()?)?;
            }
            PackageBackendRequest::Models {
                credential_headers_match: true,
            } => {
                write_json_http_response(&mut stream, "200 OK", br#"{"models":[]}"#)?;
            }
            PackageBackendRequest::Usage {
                credential_headers_match: false,
            }
            | PackageBackendRequest::ResetCredits {
                credential_headers_match: false,
            }
            | PackageBackendRequest::Models {
                credential_headers_match: false,
            } => {
                return Err("package session backend received invalid credentials".to_owned());
            }
            PackageBackendRequest::Responses(validated) => {
                observation.record_responses_call(validated)?;
                match response_mode {
                    PackageInferenceResponseMode::Complete => {
                        write_responses_http_response_and_publish(
                            &mut stream,
                            &inference_completion,
                        )?;
                    }
                    PackageInferenceResponseMode::DisconnectAfterValidatedRequest => {
                        stream
                            .shutdown(std::net::Shutdown::Both)
                            .map_err(|_| "package inference disconnect failed".to_owned())?;
                        return Ok(observation);
                    }
                }
            }
            PackageBackendRequest::Other => {
                write_unknown_package_response(&mut stream);
            }
        }
    }
}

struct RateLimitBackend {
    address: std::net::SocketAddr,
    cancel: Option<SyncSender<()>>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl RateLimitBackend {
    fn spawn() -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (cancel, cancellation) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("calcifer-package-rate-limit-backend".to_owned())
            .spawn(move || serve_rate_limit_backend(listener, cancellation))?;
        Ok(Self {
            address,
            cancel: Some(cancel),
            worker: Some(worker),
        })
    }

    const fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn join(mut self) -> Result<(), Box<dyn Error>> {
        let worker = self
            .worker
            .take()
            .ok_or("rate-limit backend worker was already joined")?;
        worker
            .join()
            .map_err(|_| "rate-limit backend worker panicked")?
            .map_err(Into::into)
    }

    fn cancel_and_join(mut self) -> Result<(), Box<dyn Error>> {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.try_send(());
        }
        let worker = self
            .worker
            .take()
            .ok_or("rate-limit backend worker was already joined")?;
        worker
            .join()
            .map_err(|_| "rate-limit backend worker panicked")?
            .map_err(Into::into)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RateLimitEndpoint {
    Usage,
    ResetCredits,
    Models,
    Responses,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedPackageResponsesRequest;

// The pinned 0.144.4 codex-api `ResponsesApiRequest` and client tests fix these
// fields and the application/json + text/event-stream media headers. Unknown
// request fields remain accepted, while the typed input projection proves the
// accepted response belongs to the one synthetic prompt driven through the
// PTY rather than to startup/background traffic.
#[derive(Deserialize)]
struct PackageResponsesRequestShape {
    model: String,
    stream: bool,
    input: PackageResponseInputProof,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PackageResponseInputProof {
    exact_current_prompt_count: u8,
}

impl<'de> Deserialize<'de> for PackageResponseInputProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct InputVisitor;

        impl<'de> Visitor<'de> for InputVisitor {
            type Value = PackageResponseInputProof;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded Codex response input sequence")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut count = 0_u8;
                while let Some(item) = sequence.next_element::<PackageResponseItemPromptProof>()? {
                    if let PackageResponseItemPromptProof::Message {
                        role: PackageResponseMessageRole::User,
                        content,
                    } = item
                    {
                        count = count.saturating_add(content.exact_current_prompt_count.min(2));
                        count = count.min(2);
                    }
                }
                Ok(PackageResponseInputProof {
                    exact_current_prompt_count: count,
                })
            }
        }

        deserializer.deserialize_seq(InputVisitor)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PackageResponseItemPromptProof {
    Message {
        role: PackageResponseMessageRole,
        content: PackageResponseContentProof,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum PackageResponseMessageRole {
    User,
    #[serde(other)]
    Other,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PackageResponseContentProof {
    exact_current_prompt_count: u8,
}

impl<'de> Deserialize<'de> for PackageResponseContentProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ContentVisitor;

        impl<'de> Visitor<'de> for ContentVisitor {
            type Value = PackageResponseContentProof;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded Codex message content sequence")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut count = 0_u8;
                while let Some(item) =
                    sequence.next_element::<PackageResponseContentPromptProof>()?
                {
                    match item {
                        PackageResponseContentPromptProof::InputText { text } if text.exact => {
                            count = count.saturating_add(1).min(2);
                        }
                        _ => {}
                    }
                }
                Ok(PackageResponseContentProof {
                    exact_current_prompt_count: count,
                })
            }
        }

        deserializer.deserialize_seq(ContentVisitor)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PackageResponseContentPromptProof {
    InputText {
        text: PackageExactPromptProof,
    },
    #[serde(other)]
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageExactPromptProof {
    exact: bool,
}

impl<'de> Deserialize<'de> for PackageExactPromptProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PromptVisitor;

        impl Visitor<'_> for PromptVisitor {
            type Value = PackageExactPromptProof;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Codex input text string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(PackageExactPromptProof {
                    exact: value == PACKAGE_SUPERVISOR_INITIAL_PROMPT,
                })
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_string(PromptVisitor)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PackageSessionBackendObservation {
    validated_responses_calls: u8,
}

impl PackageSessionBackendObservation {
    fn record_responses_call(
        &mut self,
        _request: ValidatedPackageResponsesRequest,
    ) -> Result<(), String> {
        if self.validated_responses_calls != 0 {
            return Err("package session backend received duplicate responses calls".to_owned());
        }
        self.validated_responses_calls = 1;
        Ok(())
    }

    fn require_exactly_one_responses_call(self) -> Result<(), Box<dyn Error>> {
        if self.validated_responses_calls != 1 {
            return Err(
                "package session backend did not observe exactly one responses call".into(),
            );
        }
        Ok(())
    }

    fn require_zero_responses_calls(self) -> Result<(), Box<dyn Error>> {
        if self.validated_responses_calls != 0 {
            return Err("package session backend unexpectedly observed inference".into());
        }
        Ok(())
    }
}

fn require_package_generation_inference_evidence(
    generation_started: bool,
    expectation: PackageInferenceExpectation,
    observation: PackageSessionBackendObservation,
) -> Result<(), Box<dyn Error>> {
    if generation_started {
        match expectation {
            PackageInferenceExpectation::Zero => observation.require_zero_responses_calls(),
            PackageInferenceExpectation::ExactlyOne => {
                observation.require_exactly_one_responses_call()
            }
        }
    } else {
        // Before the coordinator crosses its spawn/exec boundary there is no
        // inference generation to prove. Transport shutdown and join still
        // happen, but a zero-call observation must not be promoted to either
        // positive or negative inference evidence.
        Ok(())
    }
}

#[test]
fn package_inference_expectation_is_exhaustive_for_zero_and_exactly_one() {
    for (generation_started, expectation, calls, succeeds) in [
        (false, PackageInferenceExpectation::Zero, 0, true),
        (false, PackageInferenceExpectation::Zero, 1, true),
        (false, PackageInferenceExpectation::ExactlyOne, 0, true),
        (false, PackageInferenceExpectation::ExactlyOne, 1, true),
        (true, PackageInferenceExpectation::Zero, 0, true),
        (true, PackageInferenceExpectation::Zero, 1, false),
        (true, PackageInferenceExpectation::ExactlyOne, 0, false),
        (true, PackageInferenceExpectation::ExactlyOne, 1, true),
    ] {
        assert_eq!(
            require_package_generation_inference_evidence(
                generation_started,
                expectation,
                PackageSessionBackendObservation {
                    validated_responses_calls: calls,
                },
            )
            .is_ok(),
            succeeds,
            "started={generation_started} expectation={expectation:?} calls={calls}"
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageBackendRequest {
    Usage { credential_headers_match: bool },
    ResetCredits { credential_headers_match: bool },
    Models { credential_headers_match: bool },
    Responses(ValidatedPackageResponsesRequest),
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageBackendReadOutcome {
    Request(PackageBackendRequest),
    AbandonedBeforeRequest,
    Cancelled,
}

fn serve_rate_limit_backend(
    listener: TcpListener,
    cancellation: Receiver<()>,
) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|_| "rate-limit backend nonblocking setup failed".to_owned())?;
    let deadline = Instant::now()
        .checked_add(PROCESS_TIMEOUT)
        .ok_or_else(|| "rate-limit backend deadline overflowed".to_owned())?;
    let mut usage_requests = 0_u8;
    let mut reset_credit_requests = 0_u8;
    let mut total_requests = 0_u8;

    while usage_requests < 2 || reset_credit_requests < 2 {
        match cancellation.try_recv() {
            Ok(()) => return Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("rate-limit backend cancellation authority disappeared".to_owned());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() >= deadline {
            return Err("rate-limit backend request deadline expired".to_owned());
        }
        let (mut stream, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(_) => return Err("rate-limit backend accept failed".to_owned()),
        };
        configure_package_backend_stream(&stream).map_err(|failure| match failure {
            PackageBackendStreamSetupFailure::Blocking => {
                "rate-limit backend blocking setup failed".to_owned()
            }
            PackageBackendStreamSetupFailure::ReadTimeout
            | PackageBackendStreamSetupFailure::WriteTimeout => {
                "rate-limit backend timeout setup failed".to_owned()
            }
        })?;
        total_requests = total_requests.saturating_add(1);
        if total_requests > 16 {
            return Err("rate-limit backend received too many requests".to_owned());
        }
        let request = match read_rate_limit_request(&mut stream, &cancellation) {
            Ok(PackageBackendReadOutcome::Request(request)) => request,
            Ok(PackageBackendReadOutcome::AbandonedBeforeRequest) => continue,
            Ok(PackageBackendReadOutcome::Cancelled) => return Ok(()),
            Err(error) => {
                if package_session_backend_cancellation_requested(&cancellation)? {
                    return Ok(());
                }
                return Err(error);
            }
        };
        if package_session_backend_cancellation_requested(&cancellation)? {
            return Ok(());
        }
        match request {
            PackageBackendRequest::Usage {
                credential_headers_match: true,
            } => {
                usage_requests = usage_requests.saturating_add(1);
                if usage_requests == 1 {
                    write_json_http_response(&mut stream, "200 OK", &usage_backend_body()?)?;
                } else if usage_requests == 2 {
                    write_json_http_response(
                        &mut stream,
                        "503 Service Unavailable",
                        br#"{"error":"calcifer-private-provider-body"}"#,
                    )?;
                } else {
                    return Err("rate-limit backend received duplicate usage reads".to_owned());
                }
            }
            PackageBackendRequest::ResetCredits {
                credential_headers_match: true,
            } => {
                reset_credit_requests = reset_credit_requests.saturating_add(1);
                if reset_credit_requests == 1 {
                    write_json_http_response(&mut stream, "200 OK", &reset_credit_backend_body()?)?;
                } else if reset_credit_requests == 2 {
                    write_json_http_response(
                        &mut stream,
                        "503 Service Unavailable",
                        br#"{"error":"calcifer-private-provider-body"}"#,
                    )?;
                } else {
                    return Err(
                        "rate-limit backend received duplicate reset-credit reads".to_owned()
                    );
                }
            }
            PackageBackendRequest::Usage {
                credential_headers_match: false,
            }
            | PackageBackendRequest::ResetCredits {
                credential_headers_match: false,
            } => {
                return Err("rate-limit backend received invalid credential headers".to_owned());
            }
            PackageBackendRequest::Models {
                credential_headers_match: false,
            } => {
                return Err("rate-limit backend received invalid credential headers".to_owned());
            }
            PackageBackendRequest::Models {
                credential_headers_match: true,
            }
            | PackageBackendRequest::Responses(_)
            | PackageBackendRequest::Other => {
                write_unknown_package_response(&mut stream);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageBackendSocketRead {
    Bytes(usize),
    Closed,
    Cancelled,
    Deadline,
}

fn read_package_backend_socket(
    stream: &mut TcpStream,
    cancellation: &Receiver<()>,
    deadline: Instant,
    buffer: &mut [u8],
) -> Result<PackageBackendSocketRead, String> {
    loop {
        match stream.read(buffer) {
            Ok(0) => return Ok(PackageBackendSocketRead::Closed),
            Ok(count) => return Ok(PackageBackendSocketRead::Bytes(count)),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if package_session_backend_cancellation_requested(cancellation)? {
                    return Ok(PackageBackendSocketRead::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Ok(PackageBackendSocketRead::Deadline);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(PackageBackendSocketRead::Closed);
            }
            Err(_) => return Err("rate-limit backend request read failed".to_owned()),
        }
    }
}

fn read_rate_limit_request(
    stream: &mut TcpStream,
    cancellation: &Receiver<()>,
) -> Result<PackageBackendReadOutcome, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let initial_deadline = Instant::now() + PACKAGE_BACKEND_INITIAL_READ_TIMEOUT;
    let mut active_deadline = None;
    let header_end = loop {
        let deadline = active_deadline.unwrap_or(initial_deadline);
        let count = match read_package_backend_socket(stream, cancellation, deadline, &mut buffer)?
        {
            PackageBackendSocketRead::Bytes(count) => count,
            PackageBackendSocketRead::Closed | PackageBackendSocketRead::Deadline
                if bytes.is_empty() =>
            {
                return Ok(PackageBackendReadOutcome::AbandonedBeforeRequest);
            }
            PackageBackendSocketRead::Closed => {
                return Err("rate-limit backend request ended early".to_owned());
            }
            PackageBackendSocketRead::Deadline => {
                return Err("rate-limit backend request read failed".to_owned());
            }
            PackageBackendSocketRead::Cancelled => {
                return Ok(PackageBackendReadOutcome::Cancelled);
            }
        };
        if bytes.is_empty() {
            active_deadline = Some(Instant::now() + IO_TIMEOUT);
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_HTTP_REQUEST_BYTES {
            return Err("rate-limit backend request exceeded its bound".to_owned());
        }
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "rate-limit backend headers were invalid".to_owned())?;
    let mut lines = headers.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "rate-limit backend received an invalid request line".to_owned())?;
    let endpoint = classify_package_backend_request_line(request_line)?;
    if endpoint == RateLimitEndpoint::Other {
        // The bounded request line is sufficient to establish that this
        // connection is outside the fixture's authority. Do not validate,
        // buffer, or wait for any headers/body after the complete header
        // boundary: background requests may be encoded, malformed, or
        // cancelled mid-body, and none may terminate the shared authoritative
        // listener or retain private payload bytes.
        return Ok(PackageBackendReadOutcome::Request(
            PackageBackendRequest::Other,
        ));
    }
    let mut authorization_present = false;
    let mut authorization_matches = false;
    let mut account_present = false;
    let mut account_matches = false;
    let mut content_length_seen = false;
    let mut content_length = None;
    let mut content_type_seen = false;
    let mut content_type_matches = false;
    let mut accept_seen = false;
    let mut accept_matches = false;
    let mut content_encoding_present = false;
    let mut transfer_encoding_present = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("rate-limit backend received a malformed header".to_owned());
        };
        if name.eq_ignore_ascii_case("authorization") {
            if authorization_present {
                return Err(
                    "rate-limit backend received duplicate authorization headers".to_owned(),
                );
            }
            authorization_present = true;
            authorization_matches = value
                .trim()
                .strip_prefix("Bearer ")
                .is_some_and(|token| token == PACKAGE_FAKE_ACCESS_TOKEN);
        } else if name.eq_ignore_ascii_case("chatgpt-account-id") {
            if account_present {
                return Err("rate-limit backend received duplicate account headers".to_owned());
            }
            account_present = true;
            account_matches = value.trim() == PACKAGE_FAKE_ACCOUNT_ID;
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length_seen {
                return Err("rate-limit backend received duplicate body lengths".to_owned());
            }
            content_length_seen = true;
            content_length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type_seen {
                return Err("rate-limit backend received duplicate content types".to_owned());
            }
            content_type_seen = true;
            content_type_matches = value.trim().eq_ignore_ascii_case("application/json");
        } else if name.eq_ignore_ascii_case("accept") {
            if accept_seen {
                return Err("rate-limit backend received duplicate accept headers".to_owned());
            }
            accept_seen = true;
            accept_matches = value.trim().eq_ignore_ascii_case("text/event-stream");
        } else if name.eq_ignore_ascii_case("content-encoding") {
            content_encoding_present = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding_present = true;
        }
    }
    if endpoint == RateLimitEndpoint::Models {
        if content_length_seen
            || content_type_seen
            || content_encoding_present
            || transfer_encoding_present
        {
            return Err("package models request unexpectedly carried a body".to_owned());
        }
        return Ok(PackageBackendReadOutcome::Request(
            PackageBackendRequest::Models {
                credential_headers_match: authorization_matches && account_matches,
            },
        ));
    }
    if endpoint == RateLimitEndpoint::Responses {
        if !authorization_present || !account_present || !authorization_matches || !account_matches
        {
            return Err("package response request had invalid credential headers".to_owned());
        }
        if !content_type_seen || !content_type_matches || !accept_seen || !accept_matches {
            return Err("package response request had invalid media headers".to_owned());
        }
        if content_encoding_present || transfer_encoding_present {
            return Err("package response request used an unsupported body encoding".to_owned());
        }
        let body_length = content_length
            .filter(|length| header_end.saturating_add(*length) <= MAX_HTTP_REQUEST_BYTES)
            .ok_or_else(|| "package response request omitted a bounded body length".to_owned())?;
        if bytes[header_end..].len() > body_length {
            return Err("package response request contained trailing bytes".to_owned());
        }
        let body_end = header_end
            .checked_add(body_length)
            .ok_or_else(|| "package response request length overflowed".to_owned())?;
        let deadline = active_deadline.unwrap_or(initial_deadline);
        while bytes.len() < body_end {
            let limit = (body_end - bytes.len()).min(buffer.len());
            match read_package_backend_socket(stream, cancellation, deadline, &mut buffer[..limit])?
            {
                PackageBackendSocketRead::Bytes(count) => {
                    bytes.extend_from_slice(&buffer[..count]);
                }
                PackageBackendSocketRead::Closed => {
                    return Err("package response request body ended early".to_owned());
                }
                PackageBackendSocketRead::Deadline => {
                    return Err("rate-limit backend request read failed".to_owned());
                }
                PackageBackendSocketRead::Cancelled => {
                    return Ok(PackageBackendReadOutcome::Cancelled);
                }
            }
        }
        let body: PackageResponsesRequestShape =
            serde_json::from_slice(&bytes[header_end..body_end])
                .map_err(|_| "package response request body was invalid JSON".to_owned())?;
        if body.model != PACKAGE_SUPERVISOR_MODEL {
            return Err(
                "package response request model did not match the pinned fixture".to_owned(),
            );
        }
        if !body.stream {
            return Err("package response request was not streaming".to_owned());
        }
        match body.input.exact_current_prompt_count {
            0 => return Err("package response request omitted the fixed current prompt".to_owned()),
            1 => {}
            _ => {
                return Err(
                    "package response request duplicated the fixed current prompt".to_owned(),
                );
            }
        }
        return Ok(PackageBackendReadOutcome::Request(
            PackageBackendRequest::Responses(ValidatedPackageResponsesRequest),
        ));
    }
    let credential_headers_match = authorization_matches && account_matches;
    Ok(PackageBackendReadOutcome::Request(match endpoint {
        RateLimitEndpoint::Usage => PackageBackendRequest::Usage {
            credential_headers_match,
        },
        RateLimitEndpoint::ResetCredits => PackageBackendRequest::ResetCredits {
            credential_headers_match,
        },
        RateLimitEndpoint::Models => unreachable!("models returned after validation"),
        RateLimitEndpoint::Responses => unreachable!("responses returned after validation"),
        RateLimitEndpoint::Other => PackageBackendRequest::Other,
    }))
}

fn classify_package_backend_request_line(line: &str) -> Result<RateLimitEndpoint, String> {
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || method.is_empty()
        || method.len() > 32
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
        || !path.starts_with('/')
        || path.len() > 4096
        || path.chars().any(char::is_control)
        || version != "HTTP/1.1"
    {
        return Err("rate-limit backend received an invalid request line".to_owned());
    }
    Ok(match (method, path) {
        ("GET", "/api/codex/usage") => RateLimitEndpoint::Usage,
        ("GET", "/api/codex/rate-limit-reset-credits") => RateLimitEndpoint::ResetCredits,
        ("GET", "/v1/models?client_version=0.144.4") => RateLimitEndpoint::Models,
        ("POST", "/v1/responses") => RateLimitEndpoint::Responses,
        _ => RateLimitEndpoint::Other,
    })
}

fn usage_backend_body() -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!({
        "plan_type": "pro",
        "rate_limit": {
            "allowed": true,
            "limit_reached": false,
            "primary_window": {
                "used_percent": 42,
                "limit_window_seconds": 3600,
                "reset_after_seconds": 120,
                "reset_at": 1_735_689_720_i64
            },
            "secondary_window": {
                "used_percent": 5,
                "limit_window_seconds": 86400,
                "reset_after_seconds": 43200,
                "reset_at": 1_735_776_000_i64
            }
        },
        "rate_limit_reached_type": {
            "type": "workspace_member_usage_limit_reached"
        },
        "spend_control": {
            "reached": false,
            "individual_limit": {
                "source": "workspace_spend_controls",
                "limit": "25000",
                "used": "8000",
                "remaining": "17000",
                "used_percent": 32,
                "remaining_percent": 68,
                "reset_after_seconds": 43200,
                "reset_at": 1_735_776_000_i64
            }
        },
        "additional_rate_limits": [{
            "limit_name": "codex_other",
            "metered_feature": "codex_other",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": {
                    "used_percent": 88,
                    "limit_window_seconds": 1800,
                    "reset_after_seconds": 600,
                    "reset_at": 1_735_693_200_i64
                }
            }
        }],
        "rate_limit_reset_credits": { "available_count": 3 }
    }))
    .map_err(|_| "rate-limit backend fixture serialization failed".to_owned())
}

fn reset_credit_backend_body() -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!({
        "credits": [
            {
                "id": "calcifer-private-credit-id",
                "reset_type": "codex_rate_limits",
                "status": "available",
                "granted_at": "2026-06-17T00:00:00Z",
                "expires_at": "2026-07-17T00:00:00Z",
                "title": "calcifer-private-title",
                "description": "calcifer-private-description"
            },
            {
                "id": "calcifer-private-credit-id-2",
                "reset_type": "future_reset_type",
                "status": "future_status",
                "granted_at": "2026-06-18T00:00:00Z",
                "expires_at": null
            }
        ],
        "available_count": 2,
        "total_earned_count": 4
    }))
    .map_err(|_| "reset-credit backend fixture serialization failed".to_owned())
}

fn write_json_http_response<W: Write>(
    stream: &mut W,
    status: &str,
    body: &[u8],
) -> Result<(), String> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|_| "rate-limit backend response failed".to_owned())
}

fn write_unknown_package_response<W: Write>(stream: &mut W) {
    // Unknown background routes are outside the fixture's authority. A
    // bounded, well-formed request receives a best-effort fixed 404, but an
    // already-disconnected peer must not terminate the shared usage/inference
    // listener used by later authoritative requests.
    let _ = write_json_http_response(stream, "404 Not Found", br#"{}"#);
}

fn package_responses_sse_body() -> &'static str {
    concat!(
        "event: response.created\n",
        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"calcifer-smoke-response\"}}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"calcifer-smoke-message\",\"content\":[{\"type\":\"output_text\",\"text\":\"calcifer package current response sentinel\"}]}}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"calcifer-smoke-response\",\"usage\":{\"input_tokens\":0,\"input_tokens_details\":null,\"output_tokens\":0,\"output_tokens_details\":null,\"total_tokens\":0}}}\n\n"
    )
}

fn write_responses_http_response(stream: &mut TcpStream) -> Result<(), String> {
    let body = package_responses_sse_body();
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|_| "package response stream write failed".to_owned())
}

/// Publishes inference completion only after the client can observe HTTP EOF.
/// `flush` alone does not close the accepted socket's write half, so a client
/// using strict `read_to_end` could otherwise receive the completion signal
/// and still block behind this server's live stream owner.
fn write_responses_http_response_and_publish(
    stream: &mut TcpStream,
    inference_completion: &SyncSender<()>,
) -> Result<(), String> {
    write_responses_http_response(stream)?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| "package response stream EOF publication failed".to_owned())?;
    inference_completion
        .try_send(())
        .map_err(|_| "package session backend inference completion authority failed".to_owned())
}

struct DelayedProvider {
    address: std::net::SocketAddr,
    request_seen: Receiver<()>,
    response_release: Option<SyncSender<()>>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl DelayedProvider {
    fn spawn() -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (request_seen_sender, request_seen) = mpsc::sync_channel(1);
        let (response_release, release_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("calcifer-package-fake-provider".to_owned())
            .spawn(move || {
                serve_delayed_response(listener, request_seen_sender, release_receiver)
            })?;
        Ok(Self {
            address,
            request_seen,
            response_release: Some(response_release),
            worker: Some(worker),
        })
    }

    const fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn wait_for_request(&self, deadline: Instant) -> Result<(), Box<dyn Error>> {
        self.request_seen
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "fake provider received no running turn".into())
    }

    fn release_response(&self) -> Result<(), Box<dyn Error>> {
        self.response_release
            .as_ref()
            .ok_or("fake provider response was already released")?
            .send(())
            .map_err(|_| "fake provider response worker disappeared".into())
    }

    fn join(mut self) -> Result<(), Box<dyn Error>> {
        self.response_release = None;
        let worker = self
            .worker
            .take()
            .ok_or("fake provider worker was already joined")?;
        worker
            .join()
            .map_err(|_| "fake provider worker panicked")?
            .map_err(Into::into)
    }

    fn cancel_and_join(mut self) -> Result<(), Box<dyn Error>> {
        // A setup failure can happen before the App Server reaches the fake
        // provider. A private loopback request releases `accept`, while the
        // response permit releases an already accepted App request. No global
        // state or credential is involved in either path.
        if let Ok(mut stream) = TcpStream::connect(self.address) {
            let _ = stream.write_all(
                b"POST /v1/responses HTTP/1.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            );
            let _ = stream.flush();
        }
        let _ = self.request_seen.try_recv();
        if let Some(release) = self.response_release.take() {
            let _ = release.try_send(());
        }
        let worker = self
            .worker
            .take()
            .ok_or("fake provider worker was already joined")?;
        worker
            .join()
            .map_err(|_| "fake provider worker panicked")?
            .map_err(Into::into)
    }
}

fn serve_delayed_response(
    listener: TcpListener,
    request_seen: SyncSender<()>,
    release: Receiver<()>,
) -> Result<(), String> {
    let (mut stream, _) = listener
        .accept()
        .map_err(|_| "fake provider accept failed".to_owned())?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| "fake provider timeout setup failed".to_owned())?;
    read_bounded_http_request(&mut stream)?;
    request_seen
        .send(())
        .map_err(|_| "fake provider observer disappeared".to_owned())?;
    release
        .recv_timeout(PROCESS_TIMEOUT)
        .map_err(|_| "fake provider release timed out".to_owned())?;

    let body = package_responses_sse_body();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| "fake provider response failed".to_owned())
}

fn read_bounded_http_request(stream: &mut TcpStream) -> Result<(), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut header_end = None;
    let mut content_length = None;
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|_| "fake provider request read failed".to_owned())?;
        if count == 0 {
            return Err("fake provider request ended early".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_HTTP_REQUEST_BYTES {
            return Err("fake provider request exceeded its bound".to_owned());
        }
        let discovered_header = if header_end.is_none() {
            bytes.windows(4).position(|window| window == b"\r\n\r\n")
        } else {
            None
        };
        if let Some(index) = discovered_header {
            let end = index + 4;
            let headers = std::str::from_utf8(&bytes[..end])
                .map_err(|_| "fake provider headers were invalid".to_owned())?;
            if !headers.starts_with("POST ") || !headers.contains("/responses ") {
                return Err("fake provider received an unexpected request".to_owned());
            }
            content_length = headers.lines().find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            });
            header_end = Some(end);
        }
        let request_is_complete = match (header_end, content_length) {
            (Some(end), Some(length)) => bytes.len() >= end.saturating_add(length),
            _ => false,
        };
        if request_is_complete {
            return Ok(());
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PackageLibtestProviderActivation {
    AppServer { socket: PathBuf },
    RemoteTui { remote: PathBuf, thread_id: String },
}

fn parse_package_libtest_provider_activation(
    root: Option<&str>,
    role: Option<&str>,
    app_socket: Option<&str>,
    remote: Option<&str>,
    thread_id: Option<&str>,
) -> Result<PackageLibtestProviderActivation, Box<dyn Error>> {
    let root = parse_package_libtest_provider_root(root)?;
    match (role, app_socket, remote, thread_id) {
        (Some(PACKAGE_LIBTEST_PROVIDER_APP_ROLE), Some(socket), None, None) => {
            Ok(PackageLibtestProviderActivation::AppServer {
                socket: parse_package_libtest_runtime_socket(&root, socket, "app.sock")?,
            })
        }
        (Some(PACKAGE_LIBTEST_PROVIDER_TUI_ROLE), None, Some(remote), Some(thread_id)) => {
            if thread_id != PACKAGE_SUPERVISOR_THREAD_ID {
                return Err("libtest provider thread identity was not exact".into());
            }
            Ok(PackageLibtestProviderActivation::RemoteTui {
                remote: parse_package_libtest_runtime_socket(&root, remote, "tui.sock")?,
                thread_id: thread_id.to_owned(),
            })
        }
        _ => Err("libtest provider activation was not an exact closed role".into()),
    }
}

fn parse_package_libtest_provider_root(root: Option<&str>) -> Result<PathBuf, Box<dyn Error>> {
    let root = root
        .map(PathBuf::from)
        .filter(|root| root.is_absolute())
        .ok_or("libtest provider root was missing or relative")?;
    let metadata = fs::symlink_metadata(&root)?;
    if fs::canonicalize(&root)? != root
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || read_private_bounded(&root.join("owner.marker"), 64)? != b"calcifer-package-smoke-v1\n"
    {
        return Err("libtest provider root identity was invalid".into());
    }
    Ok(root)
}

fn parse_package_libtest_runtime_socket(
    root: &Path,
    address: &str,
    expected_filename: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let raw = address
        .strip_prefix("unix://")
        .ok_or("libtest provider address was not Unix")?;
    let path = PathBuf::from(raw);
    if path.as_os_str().as_bytes().len() > 103
        || !path.is_absolute()
        || path.file_name() != Some(OsStr::new(expected_filename))
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("libtest provider Unix address was invalid".into());
    }
    let runtime_root = root.join("r");
    let runtime_root_metadata = fs::symlink_metadata(&runtime_root)?;
    if fs::canonicalize(&runtime_root)? != runtime_root
        || !runtime_root_metadata.file_type().is_dir()
        || runtime_root_metadata.uid() != rustix::process::geteuid().as_raw()
        || runtime_root_metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("libtest provider runtime root identity was invalid".into());
    }
    let runtime = path
        .parent()
        .ok_or("libtest provider socket omitted its runtime")?;
    let runtime_metadata = fs::symlink_metadata(runtime)?;
    let runtime_name = runtime
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix(".calcifer-supervisor-"))
        .ok_or("libtest provider runtime name was invalid")?;
    let runtime_id = Uuid::parse_str(runtime_name)?;
    if fs::canonicalize(runtime)? != runtime
        || runtime.parent() != Some(runtime_root.as_path())
        || runtime_id.to_string() != runtime_name
        || !runtime_metadata.file_type().is_dir()
        || runtime_metadata.uid() != rustix::process::geteuid().as_raw()
        || runtime_metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("libtest provider runtime identity was invalid".into());
    }
    Ok(path)
}

/// Installs the one closed fake provider executable used by the deterministic
/// package matrix. The script can dispatch only the two exact production
/// managed-command shapes and sets its private activation variables only at
/// the final libtest exec boundary.
fn install_packaged_codex_provider_fixture(
    scratch: &PackageScratch,
) -> Result<PathBuf, Box<dyn Error>> {
    let helper = fs::canonicalize(std::env::current_exe()?)?;
    let helper_metadata = fs::symlink_metadata(&helper)?;
    if !helper.is_absolute()
        || !helper_metadata.file_type().is_file()
        || helper_metadata.permissions().mode() & 0o111 == 0
    {
        return Err("libtest provider helper executable was unsafe".into());
    }
    let helper = shell_quote_package_libtest(helper.as_os_str())?;
    let test = shell_quote_package_libtest(OsStr::new(PACKAGE_LIBTEST_PROVIDER_HELPER_TEST))?;
    let root = shell_quote_package_libtest(scratch.root.as_os_str())?;
    let uuid_pattern = [8_usize, 4, 4, 4, 12]
        .map(|length| "[0-9a-f]".repeat(length))
        .join("-");
    let script = format!(
        r#"#!/bin/sh
unset {role} {app_socket} {remote} {thread} {root_env}
root={root}
if [ "$#" -eq 7 ] &&
   [ "$1" = '-c' ] &&
   [ "$2" = 'cli_auth_credentials_store="file"' ] &&
   [ "$3" = '-c' ] &&
   [ "$4" = 'mcp_oauth_credentials_store="file"' ] &&
   [ "$5" = 'app-server' ] &&
   [ "$6" = '--listen' ]; then
    case "$7" in
        unix://"$root"/r/.calcifer-supervisor-{uuid_pattern}/app.sock)
            (umask 077 && printf '%s\n' dispatched > "$root/supervisor-report/app-fixture.wrapper-dispatched") || exit 65
            {role}='{app_role}' {root_env}="$root" {app_socket}="$7" exec {helper} --exact {test} --nocapture --test-threads=1
            ;;
    esac
fi
if [ "$#" -eq 9 ] &&
   [ "$1" = '-c' ] &&
   [ "$2" = 'cli_auth_credentials_store="file"' ] &&
   [ "$3" = '-c' ] &&
   [ "$4" = 'mcp_oauth_credentials_store="file"' ] &&
   [ "$5" = 'resume' ] &&
   [ "$6" = '--no-alt-screen' ] &&
   [ "$7" = '--remote' ] &&
   [ "$9" = '{thread_id}' ]; then
    case "$8" in
        unix://"$root"/r/.calcifer-supervisor-{uuid_pattern}/tui.sock)
            {role}='{tui_role}' {root_env}="$root" {remote}="$8" {thread}="$9" exec {helper} --exact {test} --nocapture --test-threads=1
            ;;
    esac
fi
if [ "$#" -ne 7 ]; then
    marker='app-fixture.wrapper-rejected-argument-count'
elif [ "$1" != '-c' ] ||
     [ "$2" != 'cli_auth_credentials_store="file"' ] ||
     [ "$3" != '-c' ] ||
     [ "$4" != 'mcp_oauth_credentials_store="file"' ]; then
    marker='app-fixture.wrapper-rejected-config'
elif [ "$5" != 'app-server' ] || [ "$6" != '--listen' ]; then
    marker='app-fixture.wrapper-rejected-command'
else
    marker='app-fixture.wrapper-rejected-socket'
fi
(umask 077 && printf '%s\n' rejected > "$root/supervisor-report/$marker") || exit 65
exit 64
"#,
        role = PACKAGE_LIBTEST_PROVIDER_ROLE_ENV,
        app_socket = PACKAGE_LIBTEST_PROVIDER_APP_SOCKET_ENV,
        remote = PACKAGE_LIBTEST_PROVIDER_REMOTE_ENV,
        thread = PACKAGE_LIBTEST_PROVIDER_THREAD_ENV,
        root_env = PACKAGE_LIBTEST_PROVIDER_ROOT_ENV,
        root = root,
        thread_id = PACKAGE_SUPERVISOR_THREAD_ID,
        app_role = PACKAGE_LIBTEST_PROVIDER_APP_ROLE,
        tui_role = PACKAGE_LIBTEST_PROVIDER_TUI_ROLE,
    );
    let path = scratch.root.join(PACKAGE_LIBTEST_PROVIDER_WRAPPER);
    write_private_executable_new(&path, script.as_bytes())?;
    Ok(fs::canonicalize(path)?)
}

fn install_packaged_tui_launcher_fixture(
    scratch: &PackageScratch,
) -> Result<PathBuf, Box<dyn Error>> {
    let helper = fs::canonicalize(std::env::current_exe()?)?;
    let helper_metadata = fs::symlink_metadata(&helper)?;
    if !helper.is_absolute()
        || !helper_metadata.file_type().is_file()
        || helper_metadata.permissions().mode() & 0o111 == 0
    {
        return Err("libtest launcher helper executable was unsafe".into());
    }
    let helper = shell_quote_package_libtest(helper.as_os_str())?;
    let test = shell_quote_package_libtest(OsStr::new(PACKAGE_LIBTEST_LAUNCHER_HELPER_TEST))?;
    let script = format!(
        r#"#!/bin/sh
if [ "$#" -ne 0 ]; then
    exit 64
fi
exec {helper} --exact {test} --nocapture --test-threads=1
"#,
    );
    let path = scratch.root.join(PACKAGE_LIBTEST_LAUNCHER_WRAPPER);
    write_private_executable_new(&path, script.as_bytes())?;
    Ok(fs::canonicalize(path)?)
}

fn shell_quote_package_libtest(value: &OsStr) -> Result<String, Box<dyn Error>> {
    let value = value
        .to_str()
        .ok_or("libtest provider shell value was not UTF-8")?;
    if value.contains(['\n', '\r', '\0']) {
        return Err("libtest provider shell value contained a control byte".into());
    }
    Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
}

fn write_private_executable_new(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() != 1
    {
        return Err("libtest provider wrapper was not private".into());
    }
    Ok(())
}

struct PackageLibtestTermination {
    pending: Arc<AtomicBool>,
    registration: Option<signal_hook::SigId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageLibtestAppPhase {
    WrapperDispatched,
    WrapperRejectedArgumentCount,
    WrapperRejectedConfig,
    WrapperRejectedCommand,
    WrapperRejectedSocket,
    RootVerified,
    SocketParentVerified,
    SocketBound,
    SocketNodeVerified,
    TerminationHandlerReady,
    CodexHomeVerified,
    WorkspaceVerified,
    TermObserved,
    HandshakeWorkerFailed,
    InitialReadWorkerFailed,
    InitialMethodWorkerFailed,
    WorkerPanicked,
    WorkerFailed,
    MonitorWorkerFailed,
    TuiWorkerFailed,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageLibtestTuiPhase {
    InferenceStarted,
    InferenceFailed,
    InferenceCompleted,
    OutputSentinelWritten,
    ExitInputObserved,
}

impl PackageLibtestTuiPhase {
    const fn marker(self) -> &'static str {
        match self {
            Self::InferenceStarted => "tui-fixture.inference-started",
            Self::InferenceFailed => "tui-fixture.inference-failed",
            Self::InferenceCompleted => "tui-fixture.inference-completed",
            Self::OutputSentinelWritten => "tui-fixture.output-sentinel-written",
            Self::ExitInputObserved => "tui-fixture.exit-input-observed",
        }
    }
}

impl PackageLibtestAppPhase {
    const fn marker(self) -> &'static str {
        match self {
            Self::WrapperDispatched => "app-fixture.wrapper-dispatched",
            Self::WrapperRejectedArgumentCount => "app-fixture.wrapper-rejected-argument-count",
            Self::WrapperRejectedConfig => "app-fixture.wrapper-rejected-config",
            Self::WrapperRejectedCommand => "app-fixture.wrapper-rejected-command",
            Self::WrapperRejectedSocket => "app-fixture.wrapper-rejected-socket",
            Self::RootVerified => "app-fixture.root-verified",
            Self::SocketParentVerified => "app-fixture.socket-parent-verified",
            Self::SocketBound => "app-fixture.socket-bound",
            Self::SocketNodeVerified => "app-fixture.socket-node-verified",
            Self::TerminationHandlerReady => "app-fixture.termination-handler-ready",
            Self::CodexHomeVerified => "app-fixture.codex-home-verified",
            Self::WorkspaceVerified => "app-fixture.workspace-verified",
            Self::TermObserved => "app-fixture.term-observed",
            Self::HandshakeWorkerFailed => "app-fixture.handshake-worker-failed",
            Self::InitialReadWorkerFailed => "app-fixture.initial-read-worker-failed",
            Self::InitialMethodWorkerFailed => "app-fixture.initial-method-worker-failed",
            Self::WorkerPanicked => "app-fixture.worker-panicked",
            Self::WorkerFailed => "app-fixture.worker-failed",
            Self::MonitorWorkerFailed => "app-fixture.monitor-worker-failed",
            Self::TuiWorkerFailed => "app-fixture.tui-worker-failed",
            Self::Complete => "app-fixture.complete",
        }
    }
}

const PACKAGE_LIBTEST_APP_PHASES: [PackageLibtestAppPhase; 21] = [
    PackageLibtestAppPhase::WrapperDispatched,
    PackageLibtestAppPhase::WrapperRejectedArgumentCount,
    PackageLibtestAppPhase::WrapperRejectedConfig,
    PackageLibtestAppPhase::WrapperRejectedCommand,
    PackageLibtestAppPhase::WrapperRejectedSocket,
    PackageLibtestAppPhase::RootVerified,
    PackageLibtestAppPhase::SocketParentVerified,
    PackageLibtestAppPhase::SocketBound,
    PackageLibtestAppPhase::SocketNodeVerified,
    PackageLibtestAppPhase::TerminationHandlerReady,
    PackageLibtestAppPhase::CodexHomeVerified,
    PackageLibtestAppPhase::WorkspaceVerified,
    PackageLibtestAppPhase::TermObserved,
    PackageLibtestAppPhase::HandshakeWorkerFailed,
    PackageLibtestAppPhase::InitialReadWorkerFailed,
    PackageLibtestAppPhase::InitialMethodWorkerFailed,
    PackageLibtestAppPhase::WorkerPanicked,
    PackageLibtestAppPhase::WorkerFailed,
    PackageLibtestAppPhase::MonitorWorkerFailed,
    PackageLibtestAppPhase::TuiWorkerFailed,
    PackageLibtestAppPhase::Complete,
];

fn latest_package_libtest_app_phase(report: &Path) -> Option<&'static str> {
    PACKAGE_LIBTEST_APP_PHASES
        .iter()
        .rev()
        .map(|phase| phase.marker())
        .find(|marker| report.join(marker).is_file())
}

#[test]
fn package_libtest_app_phase_markers_are_closed_and_fixed() {
    assert_eq!(
        PACKAGE_LIBTEST_APP_PHASES.map(PackageLibtestAppPhase::marker),
        [
            "app-fixture.wrapper-dispatched",
            "app-fixture.wrapper-rejected-argument-count",
            "app-fixture.wrapper-rejected-config",
            "app-fixture.wrapper-rejected-command",
            "app-fixture.wrapper-rejected-socket",
            "app-fixture.root-verified",
            "app-fixture.socket-parent-verified",
            "app-fixture.socket-bound",
            "app-fixture.socket-node-verified",
            "app-fixture.termination-handler-ready",
            "app-fixture.codex-home-verified",
            "app-fixture.workspace-verified",
            "app-fixture.term-observed",
            "app-fixture.handshake-worker-failed",
            "app-fixture.initial-read-worker-failed",
            "app-fixture.initial-method-worker-failed",
            "app-fixture.worker-panicked",
            "app-fixture.worker-failed",
            "app-fixture.monitor-worker-failed",
            "app-fixture.tui-worker-failed",
            "app-fixture.complete",
        ]
    );
}

#[test]
fn package_libtest_tui_phase_markers_are_closed_fixed_and_payload_free() {
    let markers = [
        PackageLibtestTuiPhase::InferenceStarted,
        PackageLibtestTuiPhase::InferenceFailed,
        PackageLibtestTuiPhase::InferenceCompleted,
        PackageLibtestTuiPhase::OutputSentinelWritten,
        PackageLibtestTuiPhase::ExitInputObserved,
    ]
    .map(PackageLibtestTuiPhase::marker);
    assert_eq!(
        markers,
        [
            "tui-fixture.inference-started",
            "tui-fixture.inference-failed",
            "tui-fixture.inference-completed",
            "tui-fixture.output-sentinel-written",
            "tui-fixture.exit-input-observed",
        ]
    );
    assert!(markers.into_iter().all(|marker| {
        marker.is_ascii()
            && marker.starts_with("tui-fixture.")
            && !marker.contains('/')
            && !marker.contains(' ')
    }));
}

fn record_package_libtest_app_phase(report: &Path, phase: PackageLibtestAppPhase) {
    record_package_diagnostic_marker(report, phase.marker());
}

fn record_package_libtest_tui_phase(report: &Path, phase: PackageLibtestTuiPhase) {
    record_package_diagnostic_marker(report, phase.marker());
}

impl PackageLibtestTermination {
    fn install() -> Result<Self, Box<dyn Error>> {
        let pending = Arc::new(AtomicBool::new(false));
        let registration = signal_hook::flag::register(
            signal_hook::consts::signal::SIGTERM,
            Arc::clone(&pending),
        )?;
        Ok(Self {
            pending,
            registration: Some(registration),
        })
    }

    fn requested(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
}

impl Drop for PackageLibtestTermination {
    fn drop(&mut self) {
        if let Some(registration) = self.registration.take() {
            let _ = signal_hook::low_level::unregister(registration);
        }
    }
}

fn run_package_libtest_app_server(socket: &Path) -> Result<(), Box<dyn Error>> {
    let root = std::env::var(PACKAGE_LIBTEST_PROVIDER_ROOT_ENV)?;
    let root = parse_package_libtest_provider_root(Some(&root))?;
    let report = checked_package_subdirectory(&root, "supervisor-report")?;
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::RootVerified);
    validate_package_libtest_socket_parent(socket)?;
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::SocketParentVerified);
    if fs::symlink_metadata(socket).is_ok() {
        return Err("libtest App Server socket already existed".into());
    }
    let listener = UnixListener::bind(socket)?;
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::SocketBound);
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let socket_metadata = fs::symlink_metadata(socket)?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.uid() != rustix::process::geteuid().as_raw()
        || socket_metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err("libtest App Server socket was not private".into());
    }
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::SocketNodeVerified);
    listener.set_nonblocking(true)?;
    let termination = PackageLibtestTermination::install()?;
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::TerminationHandlerReady);
    let codex_home = package_libtest_codex_home()?;
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::CodexHomeVerified);
    let workspace = fs::canonicalize(std::env::current_dir()?)?;
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::WorkspaceVerified);
    let mut workers: Vec<JoinHandle<Result<(), String>>> = Vec::new();
    while !termination.requested() {
        match listener.accept() {
            Ok((stream, _)) => {
                if workers.len() >= PACKAGE_LIBTEST_PROVIDER_MAX_CONNECTIONS {
                    return Err("libtest App Server received too many connections".into());
                }
                // A nonblocking handshake yields an owned MidHandshake on a
                // short read gap. The worker can then observe SIGTERM and its
                // absolute deadline without abandoning partially-read bytes.
                stream.set_nonblocking(true)?;
                let pending = Arc::clone(&termination.pending);
                let home = codex_home.clone();
                let cwd = workspace.clone();
                let worker_report = report.clone();
                workers.push(thread::spawn(move || {
                    serve_package_libtest_websocket(stream, &home, &cwd, &pending, &worker_report)
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return Err("libtest App Server accept failed".into()),
        }
    }
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::TermObserved);
    drop(listener);
    for worker in workers {
        let outcome = match worker.join() {
            Ok(outcome) => outcome,
            Err(_) => {
                record_package_libtest_app_phase(&report, PackageLibtestAppPhase::WorkerPanicked);
                return Err("libtest App Server connection panicked".into());
            }
        };
        if let Err(error) = outcome {
            record_package_libtest_app_phase(&report, PackageLibtestAppPhase::WorkerFailed);
            return Err(error.into());
        }
    }
    record_package_libtest_app_phase(&report, PackageLibtestAppPhase::Complete);
    Ok(())
}

fn validate_package_libtest_socket_parent(socket: &Path) -> Result<(), Box<dyn Error>> {
    let parent = socket
        .parent()
        .ok_or("libtest provider socket omitted its parent")?;
    let canonical = fs::canonicalize(parent)?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if canonical != parent
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("libtest provider socket parent was not private".into());
    }
    Ok(())
}

fn package_libtest_codex_home() -> Result<PathBuf, Box<dyn Error>> {
    let raw = std::env::var_os("CODEX_HOME").ok_or("libtest provider omitted CODEX_HOME")?;
    let path = PathBuf::from(raw);
    let canonical = fs::canonicalize(&path)?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if canonical != path
        || !canonical.is_absolute()
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("libtest provider CODEX_HOME was unsafe".into());
    }
    Ok(canonical)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageLibtestRpcRequest {
    id: Value,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageLibtestRpcNotification {
    method: String,
}

type PackageLibtestServerHandshake = tungstenite::handshake::server::ServerHandshake<
    UnixStream,
    tungstenite::handshake::server::NoCallback,
>;
type PackageLibtestServerHandshakeResult =
    Result<WebSocket<UnixStream>, tungstenite::HandshakeError<PackageLibtestServerHandshake>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageLibtestHandshakeFailure {
    Timeout,
    Protocol,
}

fn package_libtest_handshake_should_stop(
    error: &tungstenite::Error,
    termination_requested: bool,
) -> bool {
    package_libtest_worker_read_should_stop(error, termination_requested)
        || matches!(
            error,
            tungstenite::Error::Protocol(tungstenite::error::ProtocolError::HandshakeIncomplete)
        )
}

fn complete_package_libtest_server_handshake(
    mut result: PackageLibtestServerHandshakeResult,
    termination: &AtomicBool,
    deadline: Instant,
) -> Result<Option<WebSocket<UnixStream>>, PackageLibtestHandshakeFailure> {
    loop {
        if termination.load(Ordering::Acquire) {
            return Ok(None);
        }
        match result {
            Ok(websocket) => {
                return if Instant::now() >= deadline {
                    Err(PackageLibtestHandshakeFailure::Timeout)
                } else {
                    Ok(Some(websocket))
                };
            }
            Err(tungstenite::HandshakeError::Failure(error)) => {
                return if package_libtest_handshake_should_stop(
                    &error,
                    termination.load(Ordering::Acquire),
                ) {
                    Ok(None)
                } else {
                    Err(PackageLibtestHandshakeFailure::Protocol)
                };
            }
            Err(tungstenite::HandshakeError::Interrupted(handshake)) => {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(PackageLibtestHandshakeFailure::Timeout);
                };
                if remaining.is_zero() {
                    return Err(PackageLibtestHandshakeFailure::Timeout);
                }
                thread::sleep(remaining.min(Duration::from_millis(1)));
                result = handshake.handshake();
            }
        }
    }
}

#[test]
fn package_libtest_server_handshake_resumes_interrupted_state_with_fixed_bounds()
-> Result<(), Box<dyn Error>> {
    const REQUEST: &[u8] = concat!(
        "GET / HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "\r\n",
    )
    .as_bytes();

    let (server, mut client) = UnixStream::pair()?;
    server.set_nonblocking(true)?;
    client.write_all(&REQUEST[..1])?;
    let interrupted = accept_with_config(server, Some(package_libtest_websocket_config()));
    assert!(matches!(
        &interrupted,
        Err(tungstenite::HandshakeError::Interrupted(_))
    ));

    client.write_all(&REQUEST[1..])?;
    let termination = AtomicBool::new(false);
    let websocket = complete_package_libtest_server_handshake(
        interrupted,
        &termination,
        Instant::now() + Duration::from_secs(1),
    )
    .map_err(|_| "bounded server handshake failed")?
    .ok_or("an active handshake was misclassified as terminated")?;
    assert_eq!(
        websocket.get_config().max_message_size,
        Some(MAX_WEBSOCKET_MESSAGE_BYTES)
    );
    assert_eq!(
        websocket.get_config().max_frame_size,
        Some(MAX_WEBSOCKET_MESSAGE_BYTES)
    );
    assert!(!websocket.get_config().accept_unmasked_frames);
    drop(websocket);

    let (server, _client) = UnixStream::pair()?;
    server.set_nonblocking(true)?;
    let interrupted = accept_with_config(server, Some(package_libtest_websocket_config()));
    let termination = AtomicBool::new(true);
    assert!(
        complete_package_libtest_server_handshake(
            interrupted,
            &termination,
            Instant::now() + Duration::from_secs(1),
        )
        .map_err(|_| "terminated server handshake failed")?
        .is_none()
    );

    let (server, _client) = UnixStream::pair()?;
    server.set_nonblocking(true)?;
    let interrupted = accept_with_config(server, Some(package_libtest_websocket_config()));
    let termination = AtomicBool::new(false);
    assert!(matches!(
        complete_package_libtest_server_handshake(interrupted, &termination, Instant::now(),),
        Err(PackageLibtestHandshakeFailure::Timeout)
    ));

    assert!(package_libtest_handshake_should_stop(
        &tungstenite::Error::Protocol(tungstenite::error::ProtocolError::HandshakeIncomplete,),
        false,
    ));
    assert!(!package_libtest_handshake_should_stop(
        &tungstenite::Error::Protocol(tungstenite::error::ProtocolError::WrongHttpMethod),
        false,
    ));
    assert!(!package_libtest_handshake_should_stop(
        &tungstenite::Error::AttackAttempt,
        false,
    ));
    Ok(())
}

fn serve_package_libtest_websocket(
    stream: UnixStream,
    codex_home: &Path,
    workspace: &Path,
    termination: &AtomicBool,
    report: &Path,
) -> Result<(), String> {
    let handshake_deadline = Instant::now()
        .checked_add(IO_TIMEOUT)
        .ok_or_else(|| "libtest WebSocket handshake deadline overflowed".to_owned())?;
    let handshake = accept_with_config(stream, Some(package_libtest_websocket_config()));
    let mut websocket =
        match complete_package_libtest_server_handshake(handshake, termination, handshake_deadline)
        {
            Ok(Some(websocket)) => websocket,
            Ok(None) => return Ok(()),
            Err(_) => {
                record_package_libtest_app_phase(
                    report,
                    PackageLibtestAppPhase::HandshakeWorkerFailed,
                );
                return Err("libtest WebSocket handshake failed".to_owned());
            }
        };
    let restore_io = websocket
        .get_mut()
        .set_nonblocking(false)
        .and_then(|()| {
            websocket
                .get_mut()
                .set_read_timeout(Some(Duration::from_millis(100)))
        })
        .and_then(|()| websocket.get_mut().set_write_timeout(Some(IO_TIMEOUT)));
    if restore_io.is_err() {
        record_package_libtest_app_phase(report, PackageLibtestAppPhase::HandshakeWorkerFailed);
        return Err("libtest WebSocket handshake I/O restore failed".to_owned());
    }
    let request = match read_package_libtest_rpc_request(
        &mut websocket,
        termination,
        Instant::now() + IO_TIMEOUT,
    ) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(_) if termination.load(Ordering::Acquire) => return Ok(()),
        Err(error) => {
            record_package_libtest_app_phase(
                report,
                PackageLibtestAppPhase::InitialReadWorkerFailed,
            );
            return Err(error);
        }
    };
    let (result, failure_phase) = match request.method.as_str() {
        "initialize" => (
            serve_package_libtest_monitor(&mut websocket, request, codex_home, termination),
            PackageLibtestAppPhase::MonitorWorkerFailed,
        ),
        "thread/read" => (
            serve_package_libtest_tui_protocol(&mut websocket, request, workspace, termination),
            PackageLibtestAppPhase::TuiWorkerFailed,
        ),
        _ => {
            record_package_libtest_app_phase(
                report,
                PackageLibtestAppPhase::InitialMethodWorkerFailed,
            );
            return Err("libtest App Server received an arbitrary method".to_owned());
        }
    };
    if result.is_err() {
        record_package_libtest_app_phase(report, failure_phase);
    }
    result
}

fn package_libtest_websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WEBSOCKET_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WEBSOCKET_MESSAGE_BYTES))
        .accept_unmasked_frames(false)
}

fn serve_package_libtest_monitor(
    websocket: &mut WebSocket<UnixStream>,
    initialize: PackageLibtestRpcRequest,
    codex_home: &Path,
    termination: &AtomicBool,
) -> Result<(), String> {
    if initialize.id != json!(0)
        || initialize.params
            != Some(json!({
                "clientInfo": {
                    "name": "calcifer",
                    "title": "Calcifer",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": { "experimentalApi": false }
            }))
    {
        return Err("libtest monitor initialize request drifted".to_owned());
    }
    send_package_libtest_json(
        websocket,
        json!({
            "id": 0,
            "result": {
                "userAgent": "calcifer/0.144.4",
                "codexHome": codex_home,
                "platformFamily": "unix",
                "platformOs": std::env::consts::OS
            }
        }),
    )?;
    let Some(initialized) =
        read_package_libtest_text(websocket, termination, Instant::now() + IO_TIMEOUT)?
    else {
        return Ok(());
    };
    let initialized: PackageLibtestRpcNotification = serde_json::from_slice(&initialized)
        .map_err(|_| "libtest monitor initialized notification was invalid".to_owned())?;
    if initialized.method != "initialized" {
        return Err("libtest monitor sent an arbitrary notification".to_owned());
    }
    let mut expected_request_id = 1_u64;
    loop {
        let usage = match read_package_libtest_rpc_request(
            websocket,
            termination,
            Instant::now() + Duration::from_millis(250),
        ) {
            Ok(Some(usage)) => usage,
            Ok(None) => return Ok(()),
            Err(error) if error == "libtest provider WebSocket deadline expired" => continue,
            Err(error) => return Err(error),
        };
        if expected_request_id > PACKAGE_LIBTEST_PROVIDER_MAX_MONITOR_READS
            || usage.id.as_u64() != Some(expected_request_id)
            || usage.method != "account/rateLimits/read"
            || usage.params.is_some()
        {
            return Err("libtest monitor usage request drifted".to_owned());
        }
        send_package_libtest_json(
            websocket,
            json!({
                "id": expected_request_id,
                "result": {
                    "rateLimits": {
                        "limitId": "codex",
                        "primary": { "usedPercent": 42 }
                    }
                }
            }),
        )?;
        expected_request_id = expected_request_id
            .checked_add(1)
            .ok_or_else(|| "libtest monitor request ID overflowed".to_owned())?;
    }
}

fn serve_package_libtest_tui_protocol(
    websocket: &mut WebSocket<UnixStream>,
    read: PackageLibtestRpcRequest,
    workspace: &Path,
    termination: &AtomicBool,
) -> Result<(), String> {
    let thread_id = require_package_libtest_thread_request(&read, "thread/read")?;
    send_package_libtest_json(
        websocket,
        json!({ "id": read.id, "result": { "thread": { "id": thread_id } } }),
    )?;
    let Some(resume) =
        read_package_libtest_rpc_request(websocket, termination, Instant::now() + IO_TIMEOUT)?
    else {
        return Ok(());
    };
    let resumed_thread = require_package_libtest_thread_request(&resume, "thread/resume")?;
    if resumed_thread != thread_id {
        return Err("libtest TUI changed thread identity".to_owned());
    }
    send_package_libtest_json(
        websocket,
        json!({
            "id": resume.id,
            "result": {
                "thread": { "id": thread_id },
                "cwd": workspace,
                "model": PACKAGE_SUPERVISOR_MODEL,
                "modelProvider": "calcifer_package_smoke",
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                "sandbox": { "type": "readOnly", "networkAccess": false }
            }
        }),
    )?;
    wait_package_libtest_disconnect(websocket, termination)
}

fn require_package_libtest_thread_request<'a>(
    request: &'a PackageLibtestRpcRequest,
    method: &str,
) -> Result<&'a str, String> {
    let params = request
        .params
        .as_ref()
        .and_then(Value::as_object)
        .filter(|params| params.len() == 1)
        .ok_or_else(|| "libtest TUI request params drifted".to_owned())?;
    let thread_id = params
        .get("threadId")
        .and_then(Value::as_str)
        .ok_or_else(|| "libtest TUI request omitted thread identity".to_owned())?;
    if request.method != method
        || Uuid::parse_str(thread_id).is_err()
        || Uuid::parse_str(thread_id)
            .map(|id| id.to_string())
            .as_deref()
            != Ok(thread_id)
    {
        return Err("libtest TUI request was not canonical".to_owned());
    }
    Ok(thread_id)
}

fn read_package_libtest_rpc_request(
    websocket: &mut WebSocket<UnixStream>,
    termination: &AtomicBool,
    deadline: Instant,
) -> Result<Option<PackageLibtestRpcRequest>, String> {
    let Some(bytes) = read_package_libtest_text(websocket, termination, deadline)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "libtest provider request JSON was not exact".to_owned())
}

fn read_package_libtest_text(
    websocket: &mut WebSocket<UnixStream>,
    termination: &AtomicBool,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, String> {
    loop {
        if termination.load(Ordering::Acquire) {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err("libtest provider WebSocket deadline expired".to_owned());
        }
        match websocket.read() {
            Ok(Message::Text(text)) if text.len() <= MAX_WEBSOCKET_MESSAGE_BYTES => {
                return Ok(Some(text.as_bytes().to_vec()));
            }
            Ok(Message::Ping(bytes)) => websocket
                .send(Message::Pong(bytes))
                .map_err(|_| "libtest provider pong failed".to_owned())?,
            Ok(Message::Close(_)) => return Ok(None),
            Ok(_) => return Err("libtest provider received non-text protocol data".to_owned()),
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(1))
            }
            Err(error)
                if package_libtest_worker_read_should_stop(
                    &error,
                    termination.load(Ordering::Acquire),
                ) =>
            {
                return Ok(None);
            }
            Err(_) => return Err("libtest provider WebSocket read failed".to_owned()),
        }
    }
}

fn send_package_libtest_json(
    websocket: &mut WebSocket<UnixStream>,
    value: Value,
) -> Result<(), String> {
    let encoded = serde_json::to_vec(&value)
        .map_err(|_| "libtest provider response encoding failed".to_owned())?;
    if encoded.len() > MAX_WEBSOCKET_MESSAGE_BYTES {
        return Err("libtest provider response exceeded its bound".to_owned());
    }
    let message = Message::text(
        String::from_utf8(encoded)
            .map_err(|_| "libtest provider response was not UTF-8".to_owned())?,
    );
    match websocket.send(message) {
        Ok(()) => Ok(()),
        Err(error) if package_libtest_peer_closed(&error) => Ok(()),
        Err(_) => Err("libtest provider response send failed".to_owned()),
    }
}

fn package_libtest_peer_closed(error: &tungstenite::Error) -> bool {
    matches!(
        error,
        tungstenite::Error::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::NotConnected
            )
    ) || matches!(
        error,
        tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::ResetWithoutClosingHandshake
        ) | tungstenite::Error::ConnectionClosed
            | tungstenite::Error::AlreadyClosed
    )
}

fn package_libtest_worker_read_should_stop(
    error: &tungstenite::Error,
    termination_requested: bool,
) -> bool {
    termination_requested || package_libtest_peer_closed(error)
}

#[test]
fn package_libtest_peer_close_classification_is_closed_and_transport_only() {
    assert!(package_libtest_peer_closed(
        &tungstenite::Error::ConnectionClosed
    ));
    assert!(package_libtest_peer_closed(&tungstenite::Error::Io(
        io::Error::from(io::ErrorKind::BrokenPipe)
    )));
    assert!(!package_libtest_peer_closed(&tungstenite::Error::Io(
        io::Error::from(io::ErrorKind::PermissionDenied)
    )));
}

#[test]
fn package_libtest_worker_read_stops_on_peer_close_or_requested_termination_only() {
    let permission = tungstenite::Error::Io(io::Error::from(io::ErrorKind::PermissionDenied));
    let disconnected = tungstenite::Error::Io(io::Error::from(io::ErrorKind::NotConnected));

    assert!(!package_libtest_worker_read_should_stop(&permission, false));
    assert!(package_libtest_worker_read_should_stop(&permission, true));
    assert!(package_libtest_worker_read_should_stop(
        &disconnected,
        false
    ));
}

fn wait_package_libtest_disconnect(
    websocket: &mut WebSocket<UnixStream>,
    termination: &AtomicBool,
) -> Result<(), String> {
    loop {
        match read_package_libtest_text(
            websocket,
            termination,
            Instant::now() + Duration::from_millis(250),
        ) {
            Ok(None) => return Ok(()),
            Ok(Some(_)) => {
                return Err("libtest provider received an arbitrary extra RPC".to_owned());
            }
            Err(error) if error == "libtest provider WebSocket deadline expired" => {}
            Err(error) => return Err(error),
        }
    }
}

fn run_package_libtest_remote_tui(remote: &Path, thread_id: &str) -> Result<(), Box<dyn Error>> {
    let root = std::env::var(PACKAGE_LIBTEST_PROVIDER_ROOT_ENV)?;
    let root = parse_package_libtest_provider_root(Some(&root))?;
    let report = checked_package_subdirectory(&root, "supervisor-report")?;
    validate_package_libtest_socket_parent(remote)?;
    let remote_metadata = fs::symlink_metadata(remote)?;
    if !remote_metadata.file_type().is_socket()
        || remote_metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err("libtest TUI relay was not an owner socket".into());
    }
    let termination = PackageLibtestTermination::install()?;
    // The reviewed launcher already created and verified the TUI session
    // before exec. The fixture must validate that inherited identity rather
    // than attempting a second setsid(2) as an already-established leader.
    let proof = verify_controlling_terminal_from_stdin()?;
    if !rustix::termios::isatty(io::stdin())
        || !rustix::termios::isatty(io::stdout())
        || !rustix::termios::isatty(io::stderr())
        || proof.process() != proof.process_group()
        || proof.process() != proof.session()
        || proof.process() != proof.foreground_process_group()
    {
        return Err("libtest TUI did not own its PTY".into());
    }

    let stream = UnixStream::connect(remote)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WEBSOCKET_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WEBSOCKET_MESSAGE_BYTES));
    let (mut websocket, _) = client_with_config("ws://localhost", stream, Some(config))?;
    send_package_libtest_json(
        &mut websocket,
        json!({
            "id": 11,
            "method": "thread/read",
            "params": { "threadId": thread_id }
        }),
    )?;
    require_package_libtest_tui_response(
        &mut websocket,
        &termination.pending,
        11,
        thread_id,
        false,
    )?;
    send_package_libtest_json(
        &mut websocket,
        json!({
            "id": 12,
            "method": "thread/resume",
            "params": { "threadId": thread_id }
        }),
    )?;
    require_package_libtest_tui_response(
        &mut websocket,
        &termination.pending,
        12,
        thread_id,
        true,
    )?;

    let mut attributes = rustix::termios::tcgetattr(io::stdin())?;
    attributes.make_raw();
    rustix::termios::tcsetattr(
        io::stdin(),
        rustix::termios::OptionalActions::Now,
        &attributes,
    )?;
    io::stdout().write_all(PACKAGE_SUPERVISOR_STARTUP_SENTINEL.as_bytes())?;
    io::stdout().flush()?;

    let input_deadline = Instant::now()
        .checked_add(PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT)
        .ok_or("libtest TUI input deadline overflowed")?;
    let Some(initial) = read_package_libtest_tty_submission(&termination.pending, input_deadline)?
    else {
        return Ok(());
    };
    if initial != PACKAGE_SUPERVISOR_INITIAL_PROMPT.as_bytes() {
        return Err("libtest TUI initial prompt drifted from the fixed request".into());
    }
    record_package_libtest_tui_phase(&report, PackageLibtestTuiPhase::InferenceStarted);
    if run_package_libtest_provider_inference(&package_libtest_codex_home()?).is_err() {
        record_package_libtest_tui_phase(&report, PackageLibtestTuiPhase::InferenceFailed);
        return Err("libtest TUI fixed inference failed".into());
    }
    record_package_libtest_tui_phase(&report, PackageLibtestTuiPhase::InferenceCompleted);
    io::stdout().write_all(PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes())?;
    io::stdout().flush()?;
    record_package_libtest_tui_phase(&report, PackageLibtestTuiPhase::OutputSentinelWritten);

    let Some(exit) = read_package_libtest_tty_submission(&termination.pending, input_deadline)?
    else {
        return Ok(());
    };
    record_package_libtest_tui_phase(&report, PackageLibtestTuiPhase::ExitInputObserved);
    if exit != b"/quit" {
        return Err("libtest TUI accepted an arbitrary second input".into());
    }
    drop(websocket);
    Ok(())
}

fn require_package_libtest_tui_response(
    websocket: &mut WebSocket<UnixStream>,
    termination: &AtomicBool,
    expected_id: u64,
    expected_thread: &str,
    require_settings: bool,
) -> Result<(), Box<dyn Error>> {
    let bytes = read_package_libtest_text(websocket, termination, Instant::now() + IO_TIMEOUT)?
        .ok_or("libtest TUI server disconnected during readiness")?;
    let response: Value = serde_json::from_slice(&bytes)?;
    if response.get("id").and_then(Value::as_u64) != Some(expected_id)
        || response
            .pointer("/result/thread/id")
            .and_then(Value::as_str)
            != Some(expected_thread)
        || response.get("error").is_some()
        || (require_settings
            && response.pointer("/result/cwd").and_then(Value::as_str)
                != fs::canonicalize(std::env::current_dir()?)?.to_str())
    {
        return Err("libtest TUI readiness response drifted".into());
    }
    Ok(())
}

fn read_package_libtest_tty_submission(
    termination: &AtomicBool,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let stdin = io::stdin();
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if termination.load(Ordering::Acquire) {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err("libtest TUI input deadline expired".into());
        }
        let timeout = rustix::event::Timespec::try_from(Duration::from_millis(20))?;
        let mut descriptors = [rustix::event::PollFd::new(
            &stdin,
            rustix::event::PollFlags::IN,
        )];
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => continue,
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
                {
                    return Err("libtest TUI input poll failed".into());
                }
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        match rustix::io::read(&stdin, &mut byte) {
            Ok(0) => return Err("libtest TUI input ended early".into()),
            Ok(_) if byte[0] == b'\r' => {
                line.push(byte[0]);
                let payload = decode_package_tui_submission(&line)
                    .map_err(|error| format!("libtest TUI input framing failed: {error}"))?;
                return Ok(Some(payload.to_vec()));
            }
            Ok(_) if byte[0] == b'\n' => {
                return Err("libtest TUI input used line feed instead of Enter".into());
            }
            Ok(_) => {
                if line.len() >= PACKAGE_LIBTEST_PROVIDER_MAX_INPUT_BYTES {
                    return Err("libtest TUI input exceeded its bound".into());
                }
                line.push(byte[0]);
            }
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn decode_package_tui_submission(bytes: &[u8]) -> Result<&[u8], &'static str> {
    if !bytes.starts_with(PACKAGE_TUI_BRACKETED_PASTE_START) || bytes.last() != Some(&b'\r') {
        return Err("expected bracketed paste followed by Enter");
    }
    let framed = &bytes[..bytes.len() - 1];
    if !framed.ends_with(PACKAGE_TUI_BRACKETED_PASTE_END) {
        return Err("expected bracketed paste terminator immediately before Enter");
    }
    let payload = &framed[PACKAGE_TUI_BRACKETED_PASTE_START.len()
        ..framed.len() - PACKAGE_TUI_BRACKETED_PASTE_END.len()];
    if payload.is_empty() {
        return Err("bracketed paste payload was empty");
    }
    if payload
        .iter()
        .any(|byte| matches!(*byte, b'\r' | b'\n' | 0x1b))
    {
        return Err("bracketed paste payload contained a control delimiter");
    }
    Ok(payload)
}

fn package_libtest_provider_backend(
    codex_home: &Path,
) -> Result<std::net::SocketAddr, Box<dyn Error>> {
    let bytes = read_private_bounded(&codex_home.join("config.toml"), 64 * 1024)?;
    let config = std::str::from_utf8(&bytes)?;
    let mut addresses = config.lines().filter_map(|line| {
        line.strip_prefix("base_url = \"")
            .and_then(|value| value.strip_suffix('\"'))
    });
    let address = addresses
        .next()
        .ok_or("libtest provider config omitted its fixed base_url")?;
    if addresses.next().is_some() {
        return Err("libtest provider config duplicated its base_url".into());
    }
    let port = address
        .strip_prefix("http://127.0.0.1:")
        .and_then(|value| value.strip_suffix("/v1"))
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or("libtest provider config was not fixed loopback HTTP")?;
    let port = port.parse::<u16>()?;
    if port == 0 || address != format!("http://127.0.0.1:{port}/v1") {
        return Err("libtest provider config used a noncanonical loopback port".into());
    }
    Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
}

fn run_package_libtest_provider_inference(codex_home: &Path) -> Result<(), Box<dyn Error>> {
    let backend = package_libtest_provider_backend(codex_home)?;
    let mut stream = TcpStream::connect(backend)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&valid_package_responses_request()?)?;
    stream.flush()?;
    let mut response = Vec::new();
    Read::by_ref(&mut stream)
        .take((MAX_HTTP_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut response)?;
    if response.len() > MAX_HTTP_REQUEST_BYTES {
        return Err("libtest provider response exceeded its bound".into());
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or("libtest provider response omitted headers")?;
    let headers = std::str::from_utf8(&response[..header_end])?
        .strip_suffix("\r\n\r\n")
        .ok_or("libtest provider response header terminator drifted")?;
    let lines = headers.split("\r\n").collect::<Vec<_>>();
    if lines.len() != 4
        || lines[0] != "HTTP/1.1 200 OK"
        || lines[1] != "Content-Type: text/event-stream"
        || lines[3] != "Connection: close"
    {
        return Err("libtest provider response headers drifted".into());
    }
    let length = lines[2]
        .strip_prefix("Content-Length: ")
        .ok_or("libtest provider response omitted its length")?
        .parse::<usize>()?;
    let body = &response[header_end..];
    if length != body.len() || body != package_responses_sse_body().as_bytes() {
        return Err("libtest provider did not complete the fixed response stream".into());
    }
    Ok(())
}

struct PackageScratch {
    root: PathBuf,
    identity: (u64, u64),
    codex_home: PathBuf,
    workspace: PathBuf,
    environment_home: PathBuf,
    compatibility_stage_parent: PathBuf,
}

impl PackageScratch {
    fn create() -> Result<Self, Box<dyn Error>> {
        let parent = fs::canonicalize("/tmp")?;
        let mut root = None;
        for _ in 0..PACKAGE_SCRATCH_CREATE_ATTEMPTS {
            let nonce = Uuid::new_v4().simple().to_string();
            // Keep enough room for the production runtime nonce and both
            // Unix-domain socket names while retaining a recognizable,
            // collision-retried Calcifer prefix. The production validator
            // below remains the authority for the exact portable bound.
            let candidate = parent.join(format!("cf-{}", &nonce[..16]));
            let mut builder = fs::DirBuilder::new();
            match builder.mode(0o700).create(&candidate) {
                Ok(()) => {
                    validate_private_directory(&candidate)?;
                    root = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let root = root.ok_or("package smoke scratch nonce attempts were exhausted")?;
        let metadata = fs::symlink_metadata(&root)?;
        let identity = (metadata.dev(), metadata.ino());
        let codex_home = root.join("codex-home");
        let workspace = root.join("workspace");
        let environment_home = root.join("environment");
        let compatibility_stage_parent = root.join("s");
        for directory in [
            &codex_home,
            &workspace,
            &workspace.join(".git"),
            &environment_home,
            &environment_home.join("config"),
            &environment_home.join("data"),
            &environment_home.join("cache"),
            &environment_home.join("run"),
            &environment_home.join("tmp"),
            &compatibility_stage_parent,
        ] {
            private_directory(directory)?;
        }
        write_private_new(&root.join("owner.marker"), b"calcifer-package-smoke-v1\n")?;
        Ok(Self {
            root,
            identity,
            codex_home,
            workspace,
            environment_home,
            compatibility_stage_parent,
        })
    }

    fn validate_owned_root(&self) -> Result<(), Box<dyn Error>> {
        let metadata = fs::symlink_metadata(&self.root)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || (metadata.dev(), metadata.ino()) != self.identity
            || fs::canonicalize(&self.root)? != self.root
            || fs::read(self.root.join("owner.marker"))? != b"calcifer-package-smoke-v1\n"
        {
            return Err("package smoke scratch ownership changed; preserving it".into());
        }
        Ok(())
    }

    fn cleanup(self) -> Result<(), Box<dyn Error>> {
        self.validate_owned_root()?;
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }
}

fn private_directory(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("package smoke directory was not private".into());
    }
    Ok(())
}

pub(super) fn write_private_atomic_new(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    write_private_atomic_new_with_before_publish(path, contents, || Ok(()))
}

fn write_package_session_observation(
    report_root: &Path,
    observation: &PackagedSessionObservation,
) -> Result<(), Box<dyn Error>> {
    write_package_session_observation_with_before_publish(report_root, observation, || Ok(()))
}

fn write_package_session_observation_with_before_publish<F>(
    report_root: &Path,
    observation: &PackagedSessionObservation,
    before_publish: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    let payload = serde_json::to_vec(observation)?;
    write_private_atomic_new_with_before_publish(
        &report_root.join("session-observation.json"),
        &payload,
        before_publish,
    )
}

fn write_private_atomic_new_with_before_publish<F>(
    path: &Path,
    contents: &[u8],
    before_publish: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    let parent = path
        .parent()
        .ok_or("package atomic publication parent was missing")?;
    let name = path
        .file_name()
        .ok_or("package atomic publication name was missing")?;
    validate_private_directory(parent)?;
    let visible_parent = fs::symlink_metadata(parent)?;
    let directory = File::from(rustix::fs::open(
        parent,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let opened_parent = directory.metadata()?;
    if !opened_parent.file_type().is_dir()
        || opened_parent.uid() != rustix::process::geteuid().as_raw()
        || opened_parent.permissions().mode() & 0o7777 != 0o700
        || opened_parent.dev() != visible_parent.dev()
        || opened_parent.ino() != visible_parent.ino()
    {
        return Err("package atomic publication parent identity changed".into());
    }

    let mut temporary = None;
    for _ in 0..PRIVATE_ATOMIC_PUBLISH_ATTEMPTS {
        let temporary_name = format!(".calcifer-private-publish-{}.tmp", Uuid::new_v4());
        match rustix::fs::openat(
            directory.as_fd(),
            temporary_name.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        ) {
            Ok(descriptor) => {
                temporary = Some((temporary_name, File::from(descriptor)));
                break;
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
    }
    let (temporary_name, mut file) =
        temporary.ok_or("package atomic publication nonce attempts were exhausted")?;
    let created_metadata = file.metadata()?;
    let identity = (created_metadata.dev(), created_metadata.ino());

    let publication = (|| -> Result<(), Box<dyn Error>> {
        if !created_metadata.file_type().is_file()
            || created_metadata.uid() != rustix::process::geteuid().as_raw()
            || created_metadata.permissions().mode() & 0o7777 != 0o600
            || created_metadata.nlink() != 1
            || created_metadata.len() != 0
        {
            return Err("package atomic publication temporary was not private".into());
        }
        file.write_all(contents)?;
        file.sync_all()?;
        let durable_metadata = file.metadata()?;
        if !durable_metadata.file_type().is_file()
            || durable_metadata.uid() != rustix::process::geteuid().as_raw()
            || durable_metadata.permissions().mode() & 0o7777 != 0o600
            || durable_metadata.nlink() != 1
            || (durable_metadata.dev(), durable_metadata.ino()) != identity
            || usize::try_from(durable_metadata.len()) != Ok(contents.len())
        {
            return Err("package atomic publication temporary changed".into());
        }
        before_publish()?;
        rustix::fs::renameat_with(
            directory.as_fd(),
            temporary_name.as_str(),
            directory.as_fd(),
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)?;
        let published = File::from(rustix::fs::openat(
            directory.as_fd(),
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        let published_metadata = published.metadata()?;
        if !published_metadata.file_type().is_file()
            || published_metadata.uid() != rustix::process::geteuid().as_raw()
            || published_metadata.permissions().mode() & 0o7777 != 0o600
            || published_metadata.nlink() != 1
            || (published_metadata.dev(), published_metadata.ino()) != identity
        {
            return Err("package atomic publication identity changed".into());
        }
        directory.sync_all()?;
        Ok(())
    })();

    if publication.is_err() {
        let descriptor = rustix::fs::openat(
            directory.as_fd(),
            temporary_name.as_str(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        );
        if let Ok(descriptor) = descriptor {
            let candidate = File::from(descriptor);
            if candidate.metadata().is_ok_and(|current| {
                current.file_type().is_file()
                    && current.uid() == rustix::process::geteuid().as_raw()
                    && current.permissions().mode() & 0o7777 == 0o600
                    && current.nlink() == 1
                    && (current.dev(), current.ino()) == identity
            }) {
                drop(candidate);
                let _ = rustix::fs::unlinkat(
                    directory.as_fd(),
                    temporary_name.as_str(),
                    rustix::fs::AtFlags::empty(),
                );
                let _ = directory.sync_all();
            }
        }
    }
    publication
}

fn write_private_new(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("package smoke file was not private".into());
    }
    Ok(())
}

fn read_private_bounded(path: &Path, maximum: usize) -> std::io::Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut file = File::from(descriptor);
    let before = file.metadata()?;
    if !before.file_type().is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.permissions().mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || usize::try_from(before.len()).map_or(true, |length| length > maximum)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package smoke private file identity was invalid",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    validate_private_bounded_read_completion(&before, &after, bytes.len(), maximum)?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateBoundedReadVersion {
    length: usize,
    modified: SystemTime,
    change_time: (i64, i64),
}

impl PrivateBoundedReadVersion {
    fn capture(metadata: &fs::Metadata) -> std::io::Result<Self> {
        let length = usize::try_from(metadata.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "package smoke private file length was invalid after read",
            )
        })?;
        Ok(Self {
            length,
            modified: metadata.modified()?,
            change_time: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

fn validate_private_bounded_read_completion(
    before: &fs::Metadata,
    after: &fs::Metadata,
    bytes_read: usize,
    maximum: usize,
) -> std::io::Result<()> {
    if !after.file_type().is_file()
        || after.uid() != before.uid()
        || (after.permissions().mode() & 0o7777) != (before.permissions().mode() & 0o7777)
        || after.nlink() != before.nlink()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package smoke private file identity was invalid after read",
        ));
    }
    validate_private_bounded_read_version(
        PrivateBoundedReadVersion::capture(before)?,
        PrivateBoundedReadVersion::capture(after)?,
        bytes_read,
        maximum,
    )
}

fn validate_private_bounded_read_version(
    before: PrivateBoundedReadVersion,
    after: PrivateBoundedReadVersion,
    bytes_read: usize,
    maximum: usize,
) -> std::io::Result<()> {
    if bytes_read > maximum || after.length > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package smoke private file length was invalid after read",
        ));
    }
    if after.length > before.length {
        if bytes_read < before.length || bytes_read > after.length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "package smoke private file did not grow monotonically while read",
            ));
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "package smoke private file append progressed while read",
        ));
    }
    if after.length < before.length
        || before.modified != after.modified
        || before.change_time != after.change_time
        || after.length != bytes_read
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package smoke private file changed non-monotonically while read",
        ));
    }
    Ok(())
}

fn read_owned_evidence_bounded(path: &Path, maximum: usize) -> std::io::Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut file = File::from(descriptor);
    let before = file.metadata()?;
    let before_mode = before.permissions().mode() & 0o7777;
    if !before.file_type().is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || !matches!(before_mode, 0o600 | 0o644)
        || before.nlink() != 1
        || usize::try_from(before.len()).map_or(true, |length| length > maximum)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package network evidence file identity was invalid",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > maximum
        || !after.file_type().is_file()
        || after.uid() != before.uid()
        || after.permissions().mode() & 0o7777 != before_mode
        || after.nlink() != before.nlink()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package network evidence file changed while read",
        ));
    }
    Ok(bytes)
}
