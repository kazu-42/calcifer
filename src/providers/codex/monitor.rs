//! Typed, observe-only protocol kernel for persistent Codex usage monitoring.

use std::cell::Cell;
use std::fmt;
use std::time::Instant;

use serde::Deserialize;
use serde_json::{Value, json};

use super::json::decode_unique_json;
use super::supervisor::MonitorSessionCapability;
use super::{CodexUsage, CodexUsageError, classify_rpc_error, parse_rate_limits_result};

mod transport;

use super::supervisor::ConnectedMonitorSession;

/// Codex-wide lifecycle facade for the observe-only monitor transport.
///
/// The generic websocket and protocol implementation remains private to this
/// module. Supervised-session composition receives only startup, liveness, and
/// shutdown operations; it cannot send an arbitrary JSON-RPC method or reply
/// to a provider request.
#[must_use = "the session monitor must be shut down and joined"]
pub(in crate::providers::codex) struct SessionMonitor {
    worker: transport::MonitorWorker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::providers::codex) enum SessionMonitorError {
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

impl From<transport::MonitorTransportError> for SessionMonitorError {
    fn from(error: transport::MonitorTransportError) -> Self {
        match error {
            transport::MonitorTransportError::InvalidArgument => Self::InvalidArgument,
            transport::MonitorTransportError::Handshake => Self::Handshake,
            transport::MonitorTransportError::Protocol => Self::Protocol,
            transport::MonitorTransportError::Authentication => Self::Authentication,
            transport::MonitorTransportError::Provider => Self::Provider,
            transport::MonitorTransportError::Unsupported => Self::Unsupported,
            transport::MonitorTransportError::Timeout => Self::Timeout,
            transport::MonitorTransportError::Transport => Self::Transport,
            transport::MonitorTransportError::Worker => Self::Worker,
            transport::MonitorTransportError::AppServer => Self::AppServer,
        }
    }
}

impl fmt::Display for SessionMonitorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "the session monitor arguments were invalid",
            Self::Handshake => "the session monitor handshake failed",
            Self::Protocol => "the session monitor protocol failed",
            Self::Authentication => "the session monitor profile is not authenticated",
            Self::Provider => "the session monitor provider request failed",
            Self::Unsupported => "the session monitor contract is unsupported",
            Self::Timeout => "the session monitor timed out",
            Self::Transport => "the session monitor transport ended unexpectedly",
            Self::Worker => "the session monitor worker failed",
            Self::AppServer => "the supervised Codex App Server is not live",
        })
    }
}

impl std::error::Error for SessionMonitorError {}

#[must_use = "monitor startup failure retains the exact App Server session"]
pub(in crate::providers::codex) struct SessionMonitorStartFailure {
    session: ConnectedMonitorSession,
    error: SessionMonitorError,
}

impl SessionMonitorStartFailure {
    pub(in crate::providers::codex) fn into_session(self) -> ConnectedMonitorSession {
        self.session
    }
}

impl fmt::Debug for SessionMonitorStartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.session;
        formatter
            .debug_struct("SessionMonitorStartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[must_use = "monitor shutdown proof returns the exact App Server session"]
pub(in crate::providers::codex) struct SessionMonitorShutdownComplete {
    session: Option<ConnectedMonitorSession>,
}

impl SessionMonitorShutdownComplete {
    pub(in crate::providers::codex) fn into_session(self) -> Option<ConnectedMonitorSession> {
        self.session
    }
}

pub(in crate::providers::codex) enum SessionMonitorShutdownOwner {
    PendingJoin(Box<SessionMonitor>),
    JoinedFailed(Box<Option<ConnectedMonitorSession>>),
    JoinedPanicked(Box<Option<ConnectedMonitorSession>>),
}

#[must_use = "monitor shutdown failure retains join or App Server ownership"]
pub(in crate::providers::codex) struct SessionMonitorShutdownFailure {
    owner: SessionMonitorShutdownOwner,
    error: SessionMonitorError,
}

/// Bounded thread/turn signal projected by the typed monitor. It is an
/// observation only; this type carries no restart, reset-credit, or failover
/// authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::providers::codex) struct SessionUsageLimitSignal {
    thread_id: String,
    turn_id: String,
}

impl SessionMonitorShutdownFailure {
    pub(in crate::providers::codex) const fn error(&self) -> SessionMonitorError {
        self.error
    }

    #[expect(
        clippy::boxed_local,
        reason = "the shutdown API deliberately returns a boxed linear failure owner"
    )]
    pub(in crate::providers::codex) fn into_owner(self: Box<Self>) -> SessionMonitorShutdownOwner {
        self.owner
    }
}

impl fmt::Debug for SessionMonitorShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMonitorShutdownFailure")
            .field("error", &self.error)
            .field(
                "state",
                &match self.owner {
                    SessionMonitorShutdownOwner::PendingJoin(_) => "pending-join",
                    SessionMonitorShutdownOwner::JoinedFailed(_) => "joined-failed",
                    SessionMonitorShutdownOwner::JoinedPanicked(_) => "joined-panicked",
                },
            )
            .finish_non_exhaustive()
    }
}

impl SessionMonitor {
    /// Appends the monitor control socket and the retained App aggregate to a
    /// source-pinned child denyset.
    pub(in crate::providers::codex) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        self.worker.append_forbidden_descriptors(forbidden)
    }

    pub(in crate::providers::codex) fn spawn(
        session: ConnectedMonitorSession,
    ) -> Result<Self, Box<SessionMonitorStartFailure>> {
        transport::MonitorWorker::spawn_connected(session)
            .map(|worker| Self { worker })
            .map_err(|failure| {
                let failure = *failure;
                Box::new(SessionMonitorStartFailure {
                    error: failure.error().into(),
                    session: failure.into_session(),
                })
            })
    }

    pub(in crate::providers::codex) fn poll_ready(
        &mut self,
    ) -> Result<Option<()>, SessionMonitorError> {
        self.worker.poll_ready().map_err(Into::into)
    }

    pub(in crate::providers::codex) fn ensure_live(&mut self) -> Result<(), SessionMonitorError> {
        self.worker.ensure_live().map_err(Into::into)
    }

    pub(in crate::providers::codex) fn latest_usage(&self) -> Option<CodexUsage> {
        self.worker.latest_usage()
    }

    pub(in crate::providers::codex) fn take_usage_limit(
        &self,
    ) -> Result<Option<SessionUsageLimitSignal>, SessionMonitorError> {
        self.worker
            .take_usage_limit()
            .map(|signal| {
                signal.map(|signal| SessionUsageLimitSignal {
                    thread_id: signal.thread_id().to_owned(),
                    turn_id: signal.turn_id().to_owned(),
                })
            })
            .map_err(Into::into)
    }

    pub(in crate::providers::codex) fn shutdown(
        self,
        deadline: Instant,
    ) -> Result<SessionMonitorShutdownComplete, Box<SessionMonitorShutdownFailure>> {
        match self.worker.shutdown(deadline) {
            Ok(complete) => Ok(SessionMonitorShutdownComplete {
                session: complete.into_session(),
            }),
            Err(failure) => {
                let error = failure.error().into();
                let owner = match failure.into_owner() {
                    transport::MonitorShutdownOwner::PendingJoin(worker) => {
                        SessionMonitorShutdownOwner::PendingJoin(Box::new(Self { worker }))
                    }
                    transport::MonitorShutdownOwner::JoinedFailed(session) => {
                        SessionMonitorShutdownOwner::JoinedFailed(Box::new(session))
                    }
                    transport::MonitorShutdownOwner::JoinedPanicked(session) => {
                        SessionMonitorShutdownOwner::JoinedPanicked(Box::new(session))
                    }
                };
                Err(Box::new(SessionMonitorShutdownFailure { owner, error }))
            }
        }
    }
}

const INITIALIZE_REQUEST_ID: u64 = 0;
const FIRST_USAGE_REQUEST_ID: u64 = 1;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_METHOD_BYTES: usize = 256;
const MAX_ERROR_KIND_BYTES: usize = 128;
const MAX_TURN_STATUS_BYTES: usize = 64;
const MAX_RPC_ERROR_MESSAGE_BYTES: usize = 1024;
const MAX_RATE_LIMIT_BUCKETS: usize = 64;
const MAX_RESET_CREDIT_DETAILS: usize = 64;
const MAX_USAGE_TEXT_BYTES: usize = 256;
const MAX_DECIMAL_BYTES: usize = 128;
// Unix seconds through 9999-12-31T23:59:59Z. Provider reset metadata is
// display-only, but retaining values outside the civil timestamp domain would
// make later rendering and ordering ambiguous across platforms.
const MAX_PROVIDER_TIMESTAMP_SECONDS: i64 = 253_402_300_799;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MonitorAction {
    Outbound(MonitorCommand),
    PublishUsage(Box<CodexUsage>),
    UsageLimitExceeded { thread_id: String, turn_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MonitorCommand {
    Initialize { request_id: u64 },
    Initialized,
    ReadUsage { request_id: u64 },
}

impl MonitorCommand {
    pub(super) fn encode(&self) -> Result<Vec<u8>, MonitorError> {
        let value = match self {
            Self::Initialize { request_id } => json!({
                "id": request_id,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "calcifer",
                        "title": "Calcifer",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": { "experimentalApi": false }
                }
            }),
            Self::Initialized => json!({ "method": "initialized" }),
            Self::ReadUsage { request_id } => {
                json!({ "id": request_id, "method": "account/rateLimits/read" })
            }
        };
        serde_json::to_vec(&value).map_err(|_| MonitorError::InvalidMessage)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MonitorError {
    InvalidArgument,
    InvalidMessage,
    UnexpectedSequence,
    HomeIdentityChanged,
    Usage(CodexUsageError),
}

impl fmt::Display for MonitorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument => {
                formatter.write_str("the Codex monitor arguments were invalid")
            }
            Self::InvalidMessage => {
                formatter.write_str("the Codex monitor received an invalid message")
            }
            Self::UnexpectedSequence => {
                formatter.write_str("the Codex monitor protocol sequence was invalid")
            }
            Self::HomeIdentityChanged => {
                formatter.write_str("the selected Codex home identity changed")
            }
            Self::Usage(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for MonitorError {}

#[derive(Clone, Copy)]
enum MonitorState {
    AwaitInitialize { request_id: u64 },
    Observing { in_flight: Option<u64>, dirty: bool },
    Failed(MonitorError),
}

pub(super) struct MonitorProtocol {
    state: MonitorState,
    session: MonitorSessionCapability,
    home_identity_failed: Cell<bool>,
    next_request_id: u64,
    latest_usage: Option<CodexUsage>,
}

impl MonitorProtocol {
    /// Starts the pinned protocol against an existing managed home.
    ///
    /// The home is canonicalized once here. The initialize response must name
    /// that same canonical directory before any usage request is admitted.
    pub(super) fn start_pinned(
        session: MonitorSessionCapability,
    ) -> Result<(Self, MonitorCommand), MonitorError> {
        if session.revalidate().is_err() {
            return Err(MonitorError::InvalidArgument);
        }
        Ok((
            Self {
                state: MonitorState::AwaitInitialize {
                    request_id: INITIALIZE_REQUEST_ID,
                },
                session,
                home_identity_failed: Cell::new(false),
                next_request_id: FIRST_USAGE_REQUEST_ID,
                latest_usage: None,
            },
            MonitorCommand::Initialize {
                request_id: INITIALIZE_REQUEST_ID,
            },
        ))
    }

    #[cfg(test)]
    fn start(
        selected_codex_home: &std::path::Path,
        target_thread_id: &str,
    ) -> Result<(Self, MonitorCommand), MonitorError> {
        let session = MonitorSessionCapability::for_test(selected_codex_home, target_thread_id)
            .map_err(|_| MonitorError::InvalidArgument)?;
        Self::start_pinned(session)
    }

    pub(super) fn receive(&mut self, bytes: &[u8]) -> Result<Vec<MonitorAction>, MonitorError> {
        if let MonitorState::Failed(error) = self.state {
            return Err(error);
        }
        if !self.home_identity_is_live() {
            self.state = MonitorState::Failed(MonitorError::HomeIdentityChanged);
            return Err(MonitorError::HomeIdentityChanged);
        }
        match self.receive_inner(bytes) {
            Ok(actions) => Ok(actions),
            Err(error) => {
                self.state = MonitorState::Failed(error);
                Err(error)
            }
        }
    }

    pub(super) fn latest_usage(&self) -> Option<&CodexUsage> {
        if !self.home_identity_is_live() {
            return None;
        }
        match self.state {
            MonitorState::Observing {
                in_flight: None,
                dirty: false,
            } => self.latest_usage.as_ref(),
            MonitorState::AwaitInitialize { .. }
            | MonitorState::Observing { .. }
            | MonitorState::Failed(_) => None,
        }
    }

    /// Requests one timer-driven full refresh without synthesizing a provider
    /// notification. Repeated polls coalesce behind the current read.
    pub(super) fn request_refresh(&mut self) -> Result<Vec<MonitorAction>, MonitorError> {
        if let MonitorState::Failed(error) = self.state {
            return Err(error);
        }
        if !self.home_identity_is_live() {
            self.state = MonitorState::Failed(MonitorError::HomeIdentityChanged);
            return Err(MonitorError::HomeIdentityChanged);
        }
        let result = match self.state {
            MonitorState::AwaitInitialize { .. } => Err(MonitorError::UnexpectedSequence),
            MonitorState::Observing {
                in_flight: Some(in_flight),
                ..
            } => {
                self.state = MonitorState::Observing {
                    in_flight: Some(in_flight),
                    dirty: true,
                };
                Ok(Vec::new())
            }
            MonitorState::Observing {
                in_flight: None, ..
            } => self.issue_usage_read(),
            MonitorState::Failed(error) => Err(error),
        };
        match result {
            Ok(actions) => Ok(actions),
            Err(error) => {
                self.state = MonitorState::Failed(error);
                Err(error)
            }
        }
    }

    fn receive_inner(&mut self, bytes: &[u8]) -> Result<Vec<MonitorAction>, MonitorError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(MonitorError::InvalidMessage);
        }
        let message = decode_unique_json(bytes).map_err(|_| MonitorError::InvalidMessage)?;
        let object = message.as_object().ok_or(MonitorError::InvalidMessage)?;
        match object.get("method") {
            Some(method) => self.handle_provider_message(object, method),
            None => self.handle_response(object),
        }
    }

    fn handle_provider_message(
        &mut self,
        object: &serde_json::Map<String, Value>,
        method: &Value,
    ) -> Result<Vec<MonitorAction>, MonitorError> {
        let method = method
            .as_str()
            .filter(|method| valid_text(method, MAX_METHOD_BYTES))
            .ok_or(MonitorError::InvalidMessage)?;
        if object.contains_key("result") || object.contains_key("error") {
            return Err(MonitorError::InvalidMessage);
        }
        if let Some(id) = object.get("id") {
            if !valid_request_id(id) {
                return Err(MonitorError::InvalidMessage);
            }
            // Official App Server requests are fanned out to every initialized
            // subscriber for the thread. This observe-only connection has no
            // response API and must leave the interactive TUI authoritative;
            // ignoring the bounded valid request emits no bytes while keeping
            // subsequent resolved/turn/usage observations live.
            return Ok(Vec::new());
        }
        match method {
            "account/rateLimits/updated" => self.handle_rate_limits_updated(object.get("params")),
            "turn/completed" => self.handle_turn_completed(object.get("params")),
            _ => Ok(Vec::new()),
        }
    }

    fn handle_rate_limits_updated(
        &mut self,
        params: Option<&Value>,
    ) -> Result<Vec<MonitorAction>, MonitorError> {
        match self.state {
            MonitorState::Observing { .. } => {}
            MonitorState::AwaitInitialize { .. } => {
                return Err(MonitorError::UnexpectedSequence);
            }
            MonitorState::Failed(error) => return Err(error),
        }
        let _: WireRateLimitsUpdatedParams =
            serde_json::from_value(params.cloned().ok_or(MonitorError::InvalidMessage)?)
                .map_err(|_| MonitorError::InvalidMessage)?;
        match self.state {
            MonitorState::Observing {
                in_flight: Some(in_flight),
                ..
            } => {
                self.state = MonitorState::Observing {
                    in_flight: Some(in_flight),
                    dirty: true,
                };
                Ok(Vec::new())
            }
            MonitorState::Observing {
                in_flight: None, ..
            } => self.issue_usage_read(),
            MonitorState::AwaitInitialize { .. } => Err(MonitorError::UnexpectedSequence),
            MonitorState::Failed(error) => Err(error),
        }
    }

    fn handle_turn_completed(
        &self,
        params: Option<&Value>,
    ) -> Result<Vec<MonitorAction>, MonitorError> {
        match self.state {
            MonitorState::Observing { .. } => {}
            MonitorState::AwaitInitialize { .. } => {
                return Err(MonitorError::UnexpectedSequence);
            }
            MonitorState::Failed(error) => return Err(error),
        }
        let params = params.ok_or(MonitorError::InvalidMessage)?;
        validate_turn_completed_tags(params)?;
        let event: WireTurnCompletedParams =
            serde_json::from_value(params.clone()).map_err(|_| MonitorError::InvalidMessage)?;
        if !valid_uuid(&event.thread_id) || !valid_uuid(&event.turn.id) {
            return Err(MonitorError::InvalidMessage);
        }
        if event.thread_id != self.session.target_thread_id() {
            return Ok(Vec::new());
        }
        let usage_limit = event.turn.status == WireTurnStatus::Failed
            && matches!(
                event
                    .turn
                    .error
                    .as_ref()
                    .and_then(|error| error.codex_error_info.as_ref()),
                Some(WireCodexErrorInfo::UsageLimitExceeded)
            );
        if !usage_limit {
            return Ok(Vec::new());
        }
        Ok(vec![MonitorAction::UsageLimitExceeded {
            thread_id: event.thread_id,
            turn_id: event.turn.id,
        }])
    }

    fn handle_response(
        &mut self,
        object: &serde_json::Map<String, Value>,
    ) -> Result<Vec<MonitorAction>, MonitorError> {
        let id = object
            .get("id")
            .and_then(Value::as_u64)
            .ok_or(MonitorError::InvalidMessage)?;
        let (result, rpc_error) = match (object.get("result"), object.get("error")) {
            (Some(result), None) => (Some(result), None),
            (None, Some(error)) => (None, Some(error)),
            _ => return Err(MonitorError::InvalidMessage),
        };
        let expected_id = match self.state {
            MonitorState::AwaitInitialize { request_id } => request_id,
            MonitorState::Observing {
                in_flight: Some(request_id),
                ..
            } => request_id,
            MonitorState::Observing {
                in_flight: None, ..
            } => {
                return Err(MonitorError::UnexpectedSequence);
            }
            MonitorState::Failed(error) => return Err(error),
        };
        if id != expected_id {
            return Err(MonitorError::UnexpectedSequence);
        }
        if let Some(error) = rpc_error {
            validate_rpc_error(error)?;
            return Err(MonitorError::Usage(classify_rpc_error(error)));
        }
        let result = result.ok_or(MonitorError::InvalidMessage)?;
        match self.state {
            MonitorState::AwaitInitialize { .. } => {
                super::validate_initialize_result(
                    result.clone(),
                    self.session.selected_codex_home(),
                )
                .map_err(|error| MonitorError::Usage(error.kind))?;
                let request_id = self.take_request_id()?;
                self.state = MonitorState::Observing {
                    in_flight: Some(request_id),
                    dirty: false,
                };
                Ok(vec![
                    MonitorAction::Outbound(MonitorCommand::Initialized),
                    MonitorAction::Outbound(MonitorCommand::ReadUsage { request_id }),
                ])
            }
            MonitorState::Observing { dirty, .. } => {
                validate_usage_result(result)?;
                let usage =
                    parse_rate_limits_result(result.clone()).map_err(MonitorError::Usage)?;
                if dirty {
                    self.issue_usage_read()
                } else {
                    self.state = MonitorState::Observing {
                        in_flight: None,
                        dirty: false,
                    };
                    self.latest_usage = Some(usage.clone());
                    Ok(vec![MonitorAction::PublishUsage(Box::new(usage))])
                }
            }
            MonitorState::Failed(error) => Err(error),
        }
    }

    fn issue_usage_read(&mut self) -> Result<Vec<MonitorAction>, MonitorError> {
        let request_id = self.take_request_id()?;
        self.state = MonitorState::Observing {
            in_flight: Some(request_id),
            dirty: false,
        };
        Ok(vec![MonitorAction::Outbound(MonitorCommand::ReadUsage {
            request_id,
        })])
    }

    fn take_request_id(&mut self) -> Result<u64, MonitorError> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(MonitorError::UnexpectedSequence)?;
        Ok(request_id)
    }

    fn home_identity_is_live(&self) -> bool {
        if self.home_identity_failed.get() {
            return false;
        }
        if self.session.revalidate().is_err() {
            self.home_identity_failed.set(true);
            return false;
        }
        true
    }

    #[cfg(test)]
    pub(in crate::providers::codex) fn session_target_for_test(&self) -> (&std::path::Path, &str) {
        (
            self.session.selected_codex_home(),
            self.session.target_thread_id(),
        )
    }

    #[cfg(test)]
    pub(in crate::providers::codex) fn session_brand_for_test(&self) -> u64 {
        self.session.brand_for_test()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireRateLimitsUpdatedParams {
    #[allow(dead_code)]
    rate_limits: super::WireRateLimitSnapshot,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireTurnCompletedParams {
    thread_id: String,
    turn: WireCompletedTurn,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireCompletedTurn {
    id: String,
    status: WireTurnStatus,
    #[serde(default)]
    error: Option<WireCompletedTurnError>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireCompletedTurnError {
    #[serde(default)]
    codex_error_info: Option<WireCodexErrorInfo>,
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum WireTurnStatus {
    Completed,
    Interrupted,
    Failed,
    InProgress,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum WireCodexErrorInfo {
    ContextWindowExceeded,
    SessionBudgetExceeded,
    UsageLimitExceeded,
    ServerOverloaded,
    CyberPolicy,
    HttpConnectionFailed {
        #[serde(rename = "httpStatusCode")]
        #[allow(dead_code)]
        http_status_code: Option<u16>,
    },
    ResponseStreamConnectionFailed {
        #[serde(rename = "httpStatusCode")]
        #[allow(dead_code)]
        http_status_code: Option<u16>,
    },
    InternalServerError,
    Unauthorized,
    BadRequest,
    ThreadRollbackFailed,
    SandboxError,
    ResponseStreamDisconnected {
        #[serde(rename = "httpStatusCode")]
        #[allow(dead_code)]
        http_status_code: Option<u16>,
    },
    ResponseTooManyFailedAttempts {
        #[serde(rename = "httpStatusCode")]
        #[allow(dead_code)]
        http_status_code: Option<u16>,
    },
    ActiveTurnNotSteerable {
        #[serde(rename = "turnKind")]
        #[allow(dead_code)]
        turn_kind: WireNonSteerableTurnKind,
    },
    Other,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum WireNonSteerableTurnKind {
    Review,
    Compact,
}

fn valid_request_id(id: &Value) -> bool {
    id.as_str()
        .is_some_and(|id| valid_text(id, MAX_IDENTIFIER_BYTES))
        || id.as_i64().is_some()
        || id.as_u64().is_some()
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES)
}

fn valid_uuid(value: &str) -> bool {
    valid_identifier(value)
        && uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn validate_turn_completed_tags(params: &Value) -> Result<(), MonitorError> {
    let turn = params
        .as_object()
        .and_then(|params| params.get("turn"))
        .and_then(Value::as_object)
        .ok_or(MonitorError::InvalidMessage)?;
    if !turn
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| valid_text(status, MAX_TURN_STATUS_BYTES))
    {
        return Err(MonitorError::InvalidMessage);
    }
    let Some(error_info) = turn
        .get("error")
        .filter(|error| !error.is_null())
        .and_then(Value::as_object)
        .and_then(|error| error.get("codexErrorInfo"))
    else {
        return Ok(());
    };
    match error_info {
        Value::Null => Ok(()),
        Value::String(kind) if valid_text(kind, MAX_ERROR_KIND_BYTES) => Ok(()),
        Value::Object(kind) if kind.len() == 1 => {
            if kind
                .keys()
                .next()
                .is_some_and(|kind| valid_text(kind, MAX_ERROR_KIND_BYTES))
            {
                Ok(())
            } else {
                Err(MonitorError::InvalidMessage)
            }
        }
        _ => Err(MonitorError::InvalidMessage),
    }
}

fn validate_rpc_error(error: &Value) -> Result<(), MonitorError> {
    let error = error.as_object().ok_or(MonitorError::InvalidMessage)?;
    if error.get("code").and_then(Value::as_i64).is_none()
        || !error
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| valid_text(message, MAX_RPC_ERROR_MESSAGE_BYTES))
    {
        return Err(MonitorError::InvalidMessage);
    }
    Ok(())
}

fn validate_usage_result(result: &Value) -> Result<(), MonitorError> {
    let result = result.as_object().ok_or(MonitorError::InvalidMessage)?;
    if let Some(snapshot) = result.get("rateLimits").and_then(Value::as_object) {
        validate_rate_limit_snapshot(snapshot)?;
    }
    if let Some(by_limit_id) = result
        .get("rateLimitsByLimitId")
        .filter(|value| !value.is_null())
        .and_then(Value::as_object)
    {
        if by_limit_id.len() > MAX_RATE_LIMIT_BUCKETS {
            return Err(MonitorError::InvalidMessage);
        }
        for (limit_id, snapshot) in by_limit_id {
            if !valid_text(limit_id, MAX_USAGE_TEXT_BYTES) {
                return Err(MonitorError::InvalidMessage);
            }
            if let Some(snapshot) = snapshot.as_object() {
                validate_rate_limit_snapshot(snapshot)?;
            }
        }
    }
    if let Some(reset_credits) = result
        .get("rateLimitResetCredits")
        .filter(|value| !value.is_null())
        .and_then(Value::as_object)
    {
        let Some(details) = reset_credits
            .get("credits")
            .filter(|value| !value.is_null())
            .and_then(Value::as_array)
        else {
            return Ok(());
        };
        if details.len() > MAX_RESET_CREDIT_DETAILS {
            return Err(MonitorError::InvalidMessage);
        }
        for detail in details {
            if let Some(detail) = detail.as_object() {
                validate_optional_text(detail, "resetType", MAX_USAGE_TEXT_BYTES)?;
                validate_optional_text(detail, "status", MAX_USAGE_TEXT_BYTES)?;
                let granted_at = validate_required_provider_timestamp(detail, "grantedAt")?;
                if validate_optional_provider_timestamp(detail, "expiresAt")?
                    .is_some_and(|expires_at| expires_at < granted_at)
                {
                    return Err(MonitorError::InvalidMessage);
                }
            }
        }
    }
    Ok(())
}

fn validate_rate_limit_snapshot(
    snapshot: &serde_json::Map<String, Value>,
) -> Result<(), MonitorError> {
    for key in ["limitId", "limitName", "planType", "rateLimitReachedType"] {
        validate_optional_text(snapshot, key, MAX_USAGE_TEXT_BYTES)?;
    }
    if let Some(credits) = snapshot
        .get("credits")
        .filter(|value| !value.is_null())
        .and_then(Value::as_object)
    {
        validate_optional_decimal(credits, "balance")?;
    }
    if let Some(individual) = snapshot
        .get("individualLimit")
        .filter(|value| !value.is_null())
        .and_then(Value::as_object)
    {
        validate_required_decimal(individual, "limit")?;
        validate_required_decimal(individual, "used")?;
        validate_required_provider_timestamp(individual, "resetsAt")?;
    }
    for window in ["primary", "secondary"] {
        if let Some(window) = snapshot
            .get(window)
            .filter(|value| !value.is_null())
            .and_then(Value::as_object)
        {
            validate_optional_provider_timestamp(window, "resetsAt")?;
        }
    }
    Ok(())
}

fn validate_required_provider_timestamp(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<i64, MonitorError> {
    let timestamp = object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(MonitorError::InvalidMessage)?;
    if (0..=MAX_PROVIDER_TIMESTAMP_SECONDS).contains(&timestamp) {
        Ok(timestamp)
    } else {
        Err(MonitorError::InvalidMessage)
    }
}

fn validate_optional_provider_timestamp(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<i64>, MonitorError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => validate_required_provider_timestamp(object, key).map(Some),
    }
}

fn validate_optional_text(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<(), MonitorError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(value)) if valid_text(value, max_bytes) => Ok(()),
        Some(Value::String(_)) => Err(MonitorError::InvalidMessage),
        // The existing typed parser remains the schema authority. This layer
        // rejects only values that could otherwise become unbounded retained
        // strings; wrong JSON types are classified by that parser.
        Some(_) => Ok(()),
    }
}

fn validate_required_decimal(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), MonitorError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(MonitorError::InvalidMessage)?;
    if valid_decimal(value) {
        Ok(())
    } else {
        Err(MonitorError::InvalidMessage)
    }
}

fn validate_optional_decimal(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), MonitorError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(_) => validate_required_decimal(object, key),
    }
}

fn valid_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_DECIMAL_BYTES || !value.is_ascii() {
        return false;
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    if unsigned.is_empty() {
        return false;
    }
    let mut parts = unsigned.split('.');
    let Some(integer) = parts.next() else {
        return false;
    };
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    fraction.is_none_or(|fraction| {
        !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::{Value, json};

    use super::*;

    const TARGET_THREAD_ID: &str = "019c6e27-e55b-73d1-87d8-4e01f1f75043";
    const OTHER_THREAD_ID: &str = "019c6e27-e55b-73d1-87d8-4e01f1f75044";
    const TURN_ID: &str = "019c7714-3b77-74d1-9866-e1f484aae2ab";

    #[test]
    fn transport_error_categories_map_one_to_one_into_the_session_facade() {
        assert_eq!(
            [
                transport::MonitorTransportError::InvalidArgument,
                transport::MonitorTransportError::Handshake,
                transport::MonitorTransportError::Protocol,
                transport::MonitorTransportError::Authentication,
                transport::MonitorTransportError::Provider,
                transport::MonitorTransportError::Unsupported,
                transport::MonitorTransportError::Timeout,
                transport::MonitorTransportError::Transport,
                transport::MonitorTransportError::Worker,
                transport::MonitorTransportError::AppServer,
            ]
            .map(SessionMonitorError::from),
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
        );
    }

    #[test]
    fn monitor_shutdown_failure_exposes_only_its_closed_error_subtype() {
        let failure = SessionMonitorShutdownFailure {
            owner: SessionMonitorShutdownOwner::JoinedFailed(Box::new(None)),
            error: SessionMonitorError::Transport,
        };
        assert_eq!(failure.error(), SessionMonitorError::Transport);
    }

    #[test]
    fn initialization_emits_only_exact_pinned_messages() -> Result<(), Box<dyn std::error::Error>> {
        let home = TestDirectory::new()?;
        let (mut monitor, initialize) = MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;

        assert_eq!(
            decode_command(&initialize)?,
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
        );

        let actions = monitor.receive(&initialize_response(home.path(), "0.144.4")?)?;
        assert_eq!(actions.len(), 2);
        assert_eq!(
            outbound_value(&actions[0])?,
            json!({ "method": "initialized" })
        );
        assert_eq!(
            outbound_value(&actions[1])?,
            json!({ "id": 1, "method": "account/rateLimits/read" })
        );
        Ok(())
    }

    #[test]
    fn full_usage_response_reuses_redacted_normalization() -> Result<(), Box<dyn std::error::Error>>
    {
        let (home, mut monitor) = observing_monitor()?;
        let actions = monitor.receive(
            serde_json::to_vec(&json!({
                "id": 1,
                "result": usage_result(73, 2)
            }))?
            .as_slice(),
        )?;

        let MonitorAction::PublishUsage(usage) = &actions[0] else {
            return Err("expected a normalized usage publication".into());
        };
        assert_eq!(
            usage
                .rate_limits
                .as_ref()
                .and_then(|limits| limits.primary.as_ref())
                .map(|window| window.remaining_percent),
            Some(27)
        );
        assert_eq!(
            usage
                .reset_credits
                .as_ref()
                .map(|credits| credits.available_count),
            Some(2)
        );
        let serialized = serde_json::to_string(usage)?;
        for forbidden in ["opaque-credit-id", "provider title", "provider description"] {
            assert!(!serialized.contains(forbidden));
        }
        drop(home);
        Ok(())
    }

    #[test]
    fn rolling_update_storm_coalesces_to_one_follow_up_read()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_home, mut monitor) = observing_monitor()?;
        let update = serde_json::to_vec(&json!({
            "method": "account/rateLimits/updated",
            "params": { "rateLimits": { "primary": { "usedPercent": 100 } } }
        }))?;
        for _ in 0..100 {
            assert!(monitor.receive(&update)?.is_empty());
        }

        let actions = monitor.receive(
            serde_json::to_vec(&json!({ "id": 1, "result": usage_result(73, 2) }))?.as_slice(),
        )?;
        assert_eq!(actions.len(), 1);
        assert_eq!(
            outbound_value(&actions[0])?,
            json!({ "id": 2, "method": "account/rateLimits/read" })
        );
        Ok(())
    }

    #[test]
    fn typed_usage_limit_is_emitted_only_for_the_target_thread()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_home, mut monitor) = observing_monitor()?;
        let event = serde_json::to_vec(&json!({
            "method": "turn/completed",
            "params": {
                "threadId": TARGET_THREAD_ID,
                "turn": {
                    "id": TURN_ID,
                    "status": "failed",
                    "items": [{ "type": "userMessage", "content": "must not be retained" }],
                    "error": {
                        "message": "provider secret",
                        "codexErrorInfo": "usageLimitExceeded"
                    }
                }
            }
        }))?;

        assert_eq!(
            monitor.receive(&event)?,
            vec![MonitorAction::UsageLimitExceeded {
                thread_id: TARGET_THREAD_ID.to_owned(),
                turn_id: TURN_ID.to_owned(),
            }]
        );

        let other_thread = serde_json::to_vec(&json!({
            "method": "turn/completed",
            "params": {
                "threadId": OTHER_THREAD_ID,
                "turn": {
                    "id": TURN_ID,
                    "status": "failed",
                    "error": { "codexErrorInfo": "usageLimitExceeded" }
                }
            }
        }))?;
        assert!(monitor.receive(&other_thread)?.is_empty());
        Ok(())
    }

    #[test]
    fn semantic_notifications_before_initialize_fail_sticky_without_actions()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = TestDirectory::new()?;
        let usage_limit = serde_json::to_vec(&json!({
            "method": "turn/completed",
            "params": {
                "threadId": TARGET_THREAD_ID,
                "turn": {
                    "id": TURN_ID,
                    "status": "failed",
                    "error": { "codexErrorInfo": "usageLimitExceeded" }
                }
            }
        }))?;
        let update = serde_json::to_vec(&json!({
            "method": "account/rateLimits/updated",
            "params": { "rateLimits": { "primary": { "usedPercent": 100 } } }
        }))?;

        for first_message in [&usage_limit, &update] {
            let (mut monitor, _initialize) = MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
            assert_eq!(
                monitor.receive(first_message),
                Err(MonitorError::UnexpectedSequence)
            );
            assert_eq!(
                monitor.receive(&initialize_response(home.path(), "0.144.4")?),
                Err(MonitorError::UnexpectedSequence)
            );
            assert!(monitor.latest_usage().is_none());
        }

        let (mut timer_before_initialize, _initialize) =
            MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
        assert_eq!(
            timer_before_initialize.request_refresh(),
            Err(MonitorError::UnexpectedSequence)
        );
        assert_eq!(
            timer_before_initialize.receive(&initialize_response(home.path(), "0.144.4")?),
            Err(MonitorError::UnexpectedSequence)
        );
        Ok(())
    }

    #[test]
    fn initialize_rejects_wrong_version_or_home_and_failure_is_sticky_and_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = TestDirectory::new()?;
        let other_home = TestDirectory::new()?;
        let (mut wrong_version, _initialize) =
            MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
        let seeded_version =
            match wrong_version.receive(&initialize_response(home.path(), "0.145.0")?) {
                Ok(_) => return Err("an unpinned version must fail".into()),
                Err(error) => error,
            };
        assert_eq!(
            seeded_version,
            MonitorError::Usage(super::super::CodexUsageError::Unsupported)
        );
        assert_eq!(
            wrong_version.receive(&initialize_response(home.path(), "0.144.4")?),
            Err(seeded_version)
        );

        let (mut wrong_home, _initialize) = MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
        let error = match wrong_home.receive(&initialize_response(other_home.path(), "0.144.4")?) {
            Ok(_) => return Err("a different reported home must fail".into()),
            Err(error) => error,
        };
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(!rendered.contains(home.path().to_string_lossy().as_ref()));
            assert!(!rendered.contains(other_home.path().to_string_lossy().as_ref()));
            assert!(!rendered.contains(TARGET_THREAD_ID));
        }
        Ok(())
    }

    #[test]
    fn duplicate_keys_ambiguous_envelopes_and_unexpected_ids_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = TestDirectory::new()?;
        let (mut duplicate, _initialize) = MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
        let encoded_home = serde_json::to_string(home.path())?;
        let duplicate_message = format!(
            r#"{{"id":0,"result":{{"userAgent":"calcifer/0.144.4","codexHome":{encoded_home},"platformFamily":"unix","platformOs":"macos","platformOs":"secret-token"}}}}"#
        );
        let error = match duplicate.receive(duplicate_message.as_bytes()) {
            Ok(_) => return Err("nested duplicate keys must fail".into()),
            Err(error) => error,
        };
        assert_eq!(error, MonitorError::InvalidMessage);
        assert!(!format!("{error:?} {error}").contains("secret-token"));

        for malformed in [
            json!({ "id": 0, "result": {}, "error": { "code": -32600, "message": "raw" } }),
            json!({ "id": 0 }),
            json!({ "id": 99, "result": {} }),
        ] {
            let (mut monitor, _initialize) = MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
            assert!(monitor.receive(&serde_json::to_vec(&malformed)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn provider_requests_emit_no_action_and_leave_the_interactive_tui_authoritative()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_home, mut monitor) = observing_monitor()?;
        for id in [json!("approval-request"), json!(42)] {
            let request = serde_json::to_vec(&json!({
                "id": id,
                "method": "item/commandExecution/requestApproval",
                "params": { "command": "provider secret" }
            }))?;
            assert!(monitor.receive(&request)?.is_empty());
        }
        assert!(
            monitor
                .receive(&serde_json::to_vec(&json!({
                    "method": "serverRequest/resolved",
                    "params": { "requestId": "approval-request" }
                }))?)?
                .is_empty()
        );

        let usage = monitor.receive(&serde_json::to_vec(
            &json!({ "id": 1, "result": usage_result(10, 1) }),
        )?)?;
        assert!(matches!(usage.as_slice(), [MonitorAction::PublishUsage(_)]));
        Ok(())
    }

    #[test]
    fn usage_limit_requires_failed_status_and_exact_typed_discriminator()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_home, mut monitor) = observing_monitor()?;
        for (status, kind, message) in [
            ("completed", "usageLimitExceeded", "limit"),
            ("failed", "contextWindowExceeded", "usage limit exceeded"),
            ("interrupted", "usageLimitExceeded", "limit"),
        ] {
            let event = serde_json::to_vec(&json!({
                "method": "turn/completed",
                "params": {
                    "threadId": TARGET_THREAD_ID,
                    "turn": {
                        "id": TURN_ID,
                        "status": status,
                        "error": { "message": message, "codexErrorInfo": kind }
                    }
                }
            }))?;
            assert!(monitor.receive(&event)?.is_empty());
        }

        let structured_non_limit = serde_json::to_vec(&json!({
            "method": "turn/completed",
            "params": {
                "threadId": TARGET_THREAD_ID,
                "turn": {
                    "id": TURN_ID,
                    "status": "failed",
                    "error": {
                        "message": "transient provider error",
                        "codexErrorInfo": {
                            "httpConnectionFailed": { "httpStatusCode": 503 }
                        }
                    }
                }
            }
        }))?;
        assert!(monitor.receive(&structured_non_limit)?.is_empty());
        Ok(())
    }

    #[test]
    fn superseded_read_is_not_published_and_clean_follow_up_is_retained()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_home, mut monitor) = observing_monitor()?;
        let update = serde_json::to_vec(&json!({
            "method": "account/rateLimits/updated",
            "params": { "rateLimits": { "primary": { "usedPercent": 90 } } }
        }))?;
        assert!(monitor.receive(&update)?.is_empty());
        assert!(monitor.latest_usage().is_none());

        let superseded = monitor.receive(&serde_json::to_vec(&json!({
            "id": 1,
            "result": usage_result(50, 1)
        }))?)?;
        assert_eq!(
            outbound_value(&superseded[0])?,
            json!({ "id": 2, "method": "account/rateLimits/read" })
        );
        assert!(monitor.latest_usage().is_none());

        let clean = monitor.receive(&serde_json::to_vec(&json!({
            "id": 2,
            "result": usage_result(90, 3)
        }))?)?;
        let MonitorAction::PublishUsage(published) = &clean[0] else {
            return Err("expected clean usage publication".into());
        };
        assert_eq!(monitor.latest_usage(), Some(published.as_ref()));
        assert_eq!(
            published
                .rate_limits
                .as_ref()
                .and_then(|limits| limits.primary.as_ref())
                .map(|window| window.used_percent),
            Some(90)
        );
        Ok(())
    }

    #[test]
    fn latest_usage_is_authoritative_only_while_clean_and_healthy()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_home, mut monitor) = observing_monitor()?;
        monitor.receive(&serde_json::to_vec(&json!({
            "id": 1,
            "result": usage_result(20, 1)
        }))?)?;
        assert!(monitor.latest_usage().is_some());

        let update = serde_json::to_vec(&json!({
            "method": "account/rateLimits/updated",
            "params": { "rateLimits": { "primary": { "usedPercent": 21 } } }
        }))?;
        assert_eq!(
            outbound_value(&monitor.receive(&update)?[0])?,
            json!({ "id": 2, "method": "account/rateLimits/read" })
        );
        assert!(monitor.latest_usage().is_none());

        assert_eq!(
            monitor.receive(&serde_json::to_vec(&json!({ "id": 99, "result": {} }))?),
            Err(MonitorError::UnexpectedSequence)
        );
        assert!(monitor.latest_usage().is_none());
        Ok(())
    }

    #[test]
    fn typed_poll_reads_when_idle_without_provider_notifications()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_home, mut monitor) = observing_monitor()?;
        monitor.receive(&serde_json::to_vec(&json!({
            "id": 1,
            "result": usage_result(20, 1)
        }))?)?;

        let actions = monitor.request_refresh()?;
        assert_eq!(actions.len(), 1);
        assert_eq!(
            outbound_value(&actions[0])?,
            json!({ "id": 2, "method": "account/rateLimits/read" })
        );
        assert!(monitor.latest_usage().is_none());
        Ok(())
    }

    #[test]
    fn poll_storm_during_read_coalesces_to_one_follow_up() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_home, mut monitor) = observing_monitor()?;
        for _ in 0..100 {
            assert!(monitor.request_refresh()?.is_empty());
        }

        let actions = monitor.receive(&serde_json::to_vec(&json!({
            "id": 1,
            "result": usage_result(20, 1)
        }))?)?;
        assert_eq!(actions.len(), 1);
        assert_eq!(
            outbound_value(&actions[0])?,
            json!({ "id": 2, "method": "account/rateLimits/read" })
        );
        assert!(monitor.latest_usage().is_none());
        Ok(())
    }

    #[test]
    fn usage_snapshots_enforce_collection_and_retained_string_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut too_many_buckets = serde_json::Map::new();
        for index in 0..65 {
            too_many_buckets.insert(
                format!("bucket-{index}"),
                json!({ "primary": { "usedPercent": 1 } }),
            );
        }
        let result = json!({
            "rateLimits": { "primary": { "usedPercent": 1 } },
            "rateLimitsByLimitId": too_many_buckets
        });
        assert_usage_result_rejected(result)?;

        let mut long_name = usage_result(1, 0);
        long_name["rateLimits"]["limitName"] = json!("x".repeat(257));
        assert_usage_result_rejected(long_name)?;

        for (container, key, length) in [
            ("rateLimits", "limitId", 257),
            ("rateLimits", "planType", 257),
            ("rateLimits", "rateLimitReachedType", 257),
        ] {
            let mut result = usage_result(1, 0);
            result[container][key] = json!("x".repeat(length));
            assert_usage_result_rejected(result)?;
        }

        let mut long_map_key = usage_result(1, 0);
        long_map_key["rateLimitsByLimitId"] = json!({
            "x".repeat(257): { "primary": { "usedPercent": 1 } }
        });
        assert_usage_result_rejected(long_map_key)?;

        let mut long_balance = usage_result(1, 0);
        long_balance["rateLimits"]["credits"] = json!({
            "hasCredits": true,
            "unlimited": false,
            "balance": "1".repeat(129)
        });
        assert_usage_result_rejected(long_balance)?;

        for key in ["limit", "used"] {
            let mut long_decimal = usage_result(1, 0);
            long_decimal["rateLimits"]["individualLimit"] = json!({
                "limit": "1",
                "used": "1",
                "remainingPercent": 99,
                "resetsAt": 2
            });
            long_decimal["rateLimits"]["individualLimit"][key] = json!("1".repeat(129));
            assert_usage_result_rejected(long_decimal)?;
        }

        let mut exact_decimals = usage_result(1, 0);
        exact_decimals["rateLimits"]["credits"] = json!({
            "hasCredits": true,
            "unlimited": false,
            "balance": "1".repeat(MAX_DECIMAL_BYTES)
        });
        exact_decimals["rateLimits"]["individualLimit"] = json!({
            "limit": "1".repeat(MAX_DECIMAL_BYTES),
            "used": "-0.25",
            "remainingPercent": 99,
            "resetsAt": 2
        });
        let (_home, mut exact_monitor) = observing_monitor()?;
        assert!(
            exact_monitor
                .receive(&serde_json::to_vec(&json!({
                    "id": 1,
                    "result": exact_decimals
                }))?)
                .is_ok()
        );

        for invalid in ["provider-secret", "+1", "1e3", ".1", "1.", "--1"] {
            for pointer in [
                "/rateLimits/credits/balance",
                "/rateLimits/individualLimit/limit",
                "/rateLimits/individualLimit/used",
            ] {
                let mut result = usage_result(1, 0);
                result["rateLimits"]["credits"] = json!({
                    "hasCredits": true,
                    "unlimited": false,
                    "balance": "1"
                });
                result["rateLimits"]["individualLimit"] = json!({
                    "limit": "100",
                    "used": "1",
                    "remainingPercent": 99,
                    "resetsAt": 2
                });
                *result
                    .pointer_mut(pointer)
                    .ok_or("decimal fixture path must exist")? = json!(invalid);
                assert_usage_result_rejected(result)?;
            }
        }

        for key in ["resetType", "status"] {
            let mut long_reset_detail = usage_result(1, 1);
            long_reset_detail["rateLimitResetCredits"]["credits"][0][key] = json!("x".repeat(257));
            assert_usage_result_rejected(long_reset_detail)?;
        }

        let mut too_many_credits = usage_result(1, 65);
        too_many_credits["rateLimitResetCredits"]["credits"] = Value::Array(
            (0..65)
                .map(|_| {
                    json!({
                        "grantedAt": 1,
                        "resetType": "codexRateLimits",
                        "status": "available"
                    })
                })
                .collect(),
        );
        assert_usage_result_rejected(too_many_credits)?;
        Ok(())
    }

    #[test]
    fn oversized_input_and_unbounded_rpc_error_are_sticky_redacted_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = TestDirectory::new()?;
        let (mut oversized, _initialize) = MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
        let bytes = vec![b'x'; 1024 * 1024 + 1];
        let error = match oversized.receive(&bytes) {
            Ok(_) => return Err("oversized input must fail before JSON decoding".into()),
            Err(error) => error,
        };
        assert_eq!(error, MonitorError::InvalidMessage);
        assert_eq!(oversized.receive(b"{}"), Err(error));

        let (mut rpc, _initialize) = MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
        let provider_secret = "provider-secret".repeat(100);
        let message = serde_json::to_vec(&json!({
            "id": 0,
            "error": { "code": -32000, "message": provider_secret }
        }))?;
        let error = match rpc.receive(&message) {
            Ok(_) => {
                return Err("an unbounded RPC error must fail before lowercase allocation".into());
            }
            Err(error) => error,
        };
        assert_eq!(error, MonitorError::InvalidMessage);
        assert!(!format!("{error:?} {error}").contains("provider-secret"));
        Ok(())
    }

    #[test]
    fn start_requires_an_existing_absolute_home_and_canonical_thread_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let relative = MonitorProtocol::start(Path::new("relative-home"), TARGET_THREAD_ID)
            .err()
            .ok_or("relative home must be rejected")?;
        assert_eq!(relative, MonitorError::InvalidArgument);
        let missing = std::env::temp_dir().join("calcifer-monitor-definitely-missing-home");
        let _ = fs::remove_dir_all(&missing);
        assert_eq!(
            MonitorProtocol::start(&missing, TARGET_THREAD_ID)
                .err()
                .ok_or("missing home must be rejected")?,
            MonitorError::InvalidArgument
        );
        let home = TestDirectory::new()?;
        assert!(MonitorProtocol::start(home.path(), &TARGET_THREAD_ID.to_uppercase()).is_err());
        Ok(())
    }

    #[test]
    fn selected_home_replacement_invalidates_live_usage_and_fails_sticky()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let (home, mut monitor) = observing_monitor()?;
        monitor.receive(&serde_json::to_vec(&json!({
            "id": 1,
            "result": usage_result(20, 1)
        }))?)?;
        assert!(monitor.latest_usage().is_some());

        let moved = home.path().with_extension("original");
        fs::rename(home.path(), &moved)?;
        fs::create_dir(home.path())?;
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))?;

        assert!(
            monitor.latest_usage().is_none(),
            "a snapshot tied to a replaced managed home is not live evidence"
        );
        fs::remove_dir(home.path())?;
        fs::rename(&moved, home.path())?;
        assert_eq!(
            monitor.request_refresh(),
            Err(MonitorError::HomeIdentityChanged)
        );
        assert_eq!(
            monitor.receive(b"{}"),
            Err(MonitorError::HomeIdentityChanged),
            "the first identity failure must remain sticky"
        );

        drop(monitor);
        Ok(())
    }

    #[test]
    fn retained_provider_timestamps_have_exact_semantic_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut exact = usage_result(1, 1);
        exact["rateLimits"]["primary"]["resetsAt"] = json!(MAX_PROVIDER_TIMESTAMP_SECONDS);
        exact["rateLimits"]["individualLimit"] = json!({
            "limit": "100",
            "used": "1",
            "remainingPercent": 99,
            "resetsAt": MAX_PROVIDER_TIMESTAMP_SECONDS
        });
        exact["rateLimitResetCredits"]["credits"][0]["grantedAt"] =
            json!(MAX_PROVIDER_TIMESTAMP_SECONDS);
        exact["rateLimitResetCredits"]["credits"][0]["expiresAt"] =
            json!(MAX_PROVIDER_TIMESTAMP_SECONDS);
        let (_home, mut monitor) = observing_monitor()?;
        assert!(
            monitor
                .receive(&serde_json::to_vec(&json!({ "id": 1, "result": exact }))?)
                .is_ok()
        );

        for pointer in [
            "/rateLimits/primary/resetsAt",
            "/rateLimits/individualLimit/resetsAt",
            "/rateLimitResetCredits/credits/0/grantedAt",
            "/rateLimitResetCredits/credits/0/expiresAt",
        ] {
            for invalid in [-1, MAX_PROVIDER_TIMESTAMP_SECONDS + 1] {
                let mut result = usage_result(1, 1);
                result["rateLimits"]["primary"]["resetsAt"] = json!(1_900_000_000_i64);
                result["rateLimits"]["individualLimit"] = json!({
                    "limit": "100",
                    "used": "1",
                    "remainingPercent": 99,
                    "resetsAt": 1_900_000_000_i64
                });
                let field = result
                    .pointer_mut(pointer)
                    .ok_or("timestamp fixture path must exist")?;
                *field = json!(invalid);
                assert_usage_result_rejected(result)?;
            }
        }

        let mut backwards_expiry = usage_result(1, 1);
        backwards_expiry["rateLimitResetCredits"]["credits"][0]["grantedAt"] = json!(20);
        backwards_expiry["rateLimitResetCredits"]["credits"][0]["expiresAt"] = json!(19);
        assert_usage_result_rejected(backwards_expiry)?;
        Ok(())
    }

    fn observing_monitor() -> Result<(TestDirectory, MonitorProtocol), Box<dyn std::error::Error>> {
        let home = TestDirectory::new()?;
        let (mut monitor, _initialize) = MonitorProtocol::start(home.path(), TARGET_THREAD_ID)?;
        let actions = monitor.receive(&initialize_response(home.path(), "0.144.4")?)?;
        assert_eq!(actions.len(), 2);
        Ok((home, monitor))
    }

    fn initialize_response(home: &Path, version: &str) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&json!({
            "id": 0,
            "result": {
                "userAgent": format!("calcifer/{version}"),
                "codexHome": home,
                "platformFamily": "unix",
                "platformOs": std::env::consts::OS
            }
        }))
    }

    fn usage_result(used_percent: u32, available_count: u64) -> Value {
        json!({
            "rateLimits": {
                "limitId": "codex",
                "limitName": "Codex",
                "planType": "plus",
                "primary": { "usedPercent": used_percent }
            },
            "rateLimitResetCredits": {
                "availableCount": available_count,
                "credits": [{
                    "id": "opaque-credit-id",
                    "title": "provider title",
                    "description": "provider description",
                    "grantedAt": 1_700_000_000,
                    "expiresAt": 1_900_000_000,
                    "resetType": "codexRateLimits",
                    "status": "available"
                }]
            }
        })
    }

    fn assert_usage_result_rejected(result: Value) -> Result<(), Box<dyn std::error::Error>> {
        let (_home, mut monitor) = observing_monitor()?;
        let message = serde_json::to_vec(&json!({ "id": 1, "result": result }))?;
        assert_eq!(monitor.receive(&message), Err(MonitorError::InvalidMessage));
        Ok(())
    }

    fn decode_command(command: &MonitorCommand) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(&command.encode()?)?)
    }

    fn outbound_value(action: &MonitorAction) -> Result<Value, Box<dyn std::error::Error>> {
        let MonitorAction::Outbound(command) = action else {
            return Err("expected an outbound monitor command".into());
        };
        decode_command(command)
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Result<Self, std::io::Error> {
            use std::os::unix::fs::PermissionsExt;

            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "calcifer-monitor-test-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self {
                path: fs::canonicalize(path)?,
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
