//! Read-only Codex account usage through the official app-server protocol.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const CLI_FILE_CREDENTIALS_OVERRIDE: &str = r#"cli_auth_credentials_store="file""#;
pub(crate) const MCP_OAUTH_FILE_CREDENTIALS_OVERRIDE: &str =
    r#"mcp_oauth_credentials_store="file""#;

const MANAGED_ENVIRONMENT_DENYLIST: &[&str] = &[
    "OPENAI_API_KEY",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT",
    "CODEX_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
    "CODEX_REVOKE_TOKEN_URL_OVERRIDE",
    "CODEX_APP_SERVER_LOGIN_CLIENT_ID",
    "CODEX_AUTHAPI_BASE_URL",
    "CODEX_APP_SERVER_LOGIN_ISSUER",
    "CODEX_APP_SERVER_DEV_OPEN_APP_URL",
    "CODEX_APP_SERVER_MANAGED_CONFIG_PATH",
    "CODEX_APP_SERVER_DISABLE_MANAGED_CONFIG",
    "CODEX_APP_SERVER_TEST_USER_CONFIG_FILE",
    "CODEX_SQLITE_HOME",
    "CODEX_REMOTE_AUTH_TOKEN",
    "CODEX_CONNECTORS_TOKEN",
    "CODEX_CODE_MODE_HOST_PATH",
    "CODEX_STARTING_DIFF",
    "CODEX_INTERNAL_ORIGINATOR_OVERRIDE",
    "CODEX_TUI_RECORD_SESSION",
    "CODEX_TUI_SESSION_LOG_PATH",
    "CODEX_ROLLOUT_TRACE_ROOT",
    "CODEX_ANALYTICS_EVENTS_CAPTURE_FILE",
];

const MAX_JSONL_LINE_BYTES: usize = 1024 * 1024;
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// Builds a Codex command bound to one managed credential and state home.
///
/// Provider-owned authentication and development overrides are removed from
/// the inherited environment so ambient shell or repository tooling cannot
/// replace the profile selected by Calcifer.
pub(crate) fn managed_command(executable: &Path, codex_home: &Path) -> Command {
    let mut command = Command::new(executable);
    sanitize_managed_environment(&mut command);
    command
        .args([
            "-c",
            CLI_FILE_CREDENTIALS_OVERRIDE,
            "-c",
            MCP_OAUTH_FILE_CREDENTIALS_OVERRIDE,
        ])
        .env("CODEX_HOME", codex_home);

    command
}

/// Removes provider-owned secrets and routing controls before a process in the
/// managed Codex launch chain starts.
pub(crate) fn sanitize_managed_environment(command: &mut Command) {
    for name in MANAGED_ENVIRONMENT_DENYLIST {
        command.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        if is_managed_environment_override(&name) {
            command.env_remove(name);
        }
    }
}

fn is_managed_environment_override(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let normalized = name.to_ascii_uppercase();
    MANAGED_ENVIRONMENT_DENYLIST.contains(&normalized.as_str())
        || normalized.starts_with("CODEX_TEST_")
        || normalized.starts_with("CODEX_CLOUD_TASKS_")
        || normalized.starts_with("CODEX_EXEC_SERVER_")
        || normalized.starts_with("CODEX_OSS_")
        || (normalized.starts_with("CODEX_") && normalized.ends_with("_OVERRIDE"))
}

/// A normalized Codex account usage snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CodexUsage {
    pub rate_limits: Option<RateLimitSnapshot>,
    pub rate_limits_by_limit_id: BTreeMap<String, RateLimitSnapshot>,
    pub reset_credits: Option<ResetCredits>,
}

/// A normalized rate-limit bucket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RateLimitSnapshot {
    pub limit_id: Option<String>,
    pub limit_name: Option<String>,
    pub plan_type: Option<String>,
    pub rate_limit_reached_type: Option<String>,
    pub primary: Option<RateLimitWindow>,
    pub secondary: Option<RateLimitWindow>,
    pub credits: Option<CreditsSnapshot>,
    pub individual_limit: Option<SpendControlLimitSnapshot>,
}

/// Usage and reset information for one rate-limit window.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RateLimitWindow {
    pub used_percent: u32,
    /// Display-only complement of `used_percent`, clamped to zero.
    ///
    /// Callers must not treat zero as authoritative exhaustion without a fresh
    /// provider observation or an explicit rate-limit error.
    pub remaining_percent: u32,
    pub window_duration_mins: Option<u64>,
    pub resets_at: Option<i64>,
}

/// The account's additional-credit state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CreditsSnapshot {
    pub has_credits: bool,
    pub unlimited: bool,
    pub balance: Option<String>,
}

/// An optional account-level spend control reported by Codex.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SpendControlLimitSnapshot {
    pub limit: String,
    pub used: String,
    pub remaining_percent: u32,
    pub resets_at: i64,
}

/// Reset-credit availability and optional non-opaque detail.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResetCredits {
    pub available_count: u64,
    pub details: Option<Vec<ResetCreditDetail>>,
}

/// Safe reset-credit fields exposed to Calcifer callers.
///
/// Opaque provider IDs and backend display copy are intentionally excluded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResetCreditDetail {
    pub granted_at: i64,
    pub expires_at: Option<i64>,
    pub reset_type: String,
    pub status: String,
}

/// A redacted failure category for Codex usage reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexUsageError {
    Unsupported,
    Protocol,
    Authentication,
    Timeout,
    Spawn,
}

impl fmt::Display for CodexUsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unsupported => "the Codex app-server does not support account usage reads",
            Self::Protocol => "the Codex app-server returned an invalid protocol response",
            Self::Authentication => "the Codex profile is not authenticated",
            Self::Timeout => "the Codex app-server usage read timed out",
            Self::Spawn => "the Codex app-server could not be started",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CodexUsageError {}

/// Reads one account usage snapshot from the official Codex app-server.
pub fn read_account_usage(
    codex_executable: &Path,
    codex_home: &Path,
    working_directory: &Path,
    timeout: Duration,
) -> Result<CodexUsage, CodexUsageError> {
    if !codex_executable.is_absolute() {
        return Err(CodexUsageError::Spawn);
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(CodexUsageError::Timeout)?;
    let mut process = AppServerProcess::spawn(codex_executable, codex_home, working_directory)?;

    process.send(&json!({
        "id": INITIALIZE_REQUEST_ID,
        "method": "initialize",
        "params": {
            "clientInfo": {
                "name": "calcifer",
                "title": "Calcifer",
                "version": env!("CARGO_PKG_VERSION")
            },
            "capabilities": {
                "experimentalApi": false
            }
        }
    }))?;
    let initialize_result = process.receive_result(INITIALIZE_REQUEST_ID, deadline)?;
    if !initialize_result.is_object() {
        return Err(CodexUsageError::Protocol);
    }

    process.send(&json!({ "method": "initialized", "params": {} }))?;
    process.send(&json!({
        "id": RATE_LIMITS_REQUEST_ID,
        "method": "account/rateLimits/read",
        "params": null
    }))?;

    let result = process.receive_result(RATE_LIMITS_REQUEST_ID, deadline)?;
    parse_rate_limits_result(result)
}

const INITIALIZE_REQUEST_ID: u64 = 0;
const RATE_LIMITS_REQUEST_ID: u64 = 1;

struct AppServerProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout_events: Option<Receiver<StdoutEvent>>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_drainer: Option<JoinHandle<()>>,
}

impl AppServerProcess {
    fn spawn(
        codex_executable: &Path,
        codex_home: &Path,
        working_directory: &Path,
    ) -> Result<Self, CodexUsageError> {
        let mut child = managed_command(codex_executable, codex_home)
            .args(["app-server", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(working_directory)
            .spawn()
            .map_err(|_| CodexUsageError::Spawn)?;

        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                terminate(&mut child);
                return Err(CodexUsageError::Spawn);
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate(&mut child);
                return Err(CodexUsageError::Spawn);
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                terminate(&mut child);
                return Err(CodexUsageError::Spawn);
            }
        };

        let (stdout_sender, stdout_events) = mpsc::sync_channel(16);
        let stdout_reader = match thread::Builder::new()
            .name("calcifer-codex-stdout".to_owned())
            .spawn(move || read_stdout(stdout, &stdout_sender))
        {
            Ok(reader) => reader,
            Err(_) => {
                terminate(&mut child);
                return Err(CodexUsageError::Spawn);
            }
        };
        let stderr_drainer = match thread::Builder::new()
            .name("calcifer-codex-stderr".to_owned())
            .spawn(move || drain_stderr(stderr))
        {
            Ok(drainer) => drainer,
            Err(_) => {
                terminate(&mut child);
                return Err(CodexUsageError::Spawn);
            }
        };

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout_events: Some(stdout_events),
            stdout_reader: Some(stdout_reader),
            stderr_drainer: Some(stderr_drainer),
        })
    }

    fn send(&mut self, message: &Value) -> Result<(), CodexUsageError> {
        let stdin = self.stdin.as_mut().ok_or(CodexUsageError::Protocol)?;
        serde_json::to_writer(&mut *stdin, message).map_err(|_| CodexUsageError::Protocol)?;
        stdin
            .write_all(b"\n")
            .and_then(|()| stdin.flush())
            .map_err(|_| CodexUsageError::Protocol)
    }

    fn receive_result(
        &self,
        expected_id: u64,
        deadline: Instant,
    ) -> Result<Value, CodexUsageError> {
        let events = self
            .stdout_events
            .as_ref()
            .ok_or(CodexUsageError::Protocol)?;
        receive_result_from(events, expected_id, deadline)
    }
}

fn receive_result_from(
    events: &Receiver<StdoutEvent>,
    expected_id: u64,
    deadline: Instant,
) -> Result<Value, CodexUsageError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(CodexUsageError::Timeout)?;
        let event = match events.recv_timeout(remaining) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => return Err(CodexUsageError::Timeout),
            Err(RecvTimeoutError::Disconnected) => return Err(CodexUsageError::Protocol),
        };
        let line = match event {
            StdoutEvent::Line(line) => line,
            StdoutEvent::ReadError | StdoutEvent::Eof => {
                return Err(CodexUsageError::Protocol);
            }
        };
        if let Some(result) = decode_response(&line, expected_id)? {
            return Ok(result);
        }
    }
}

impl Drop for AppServerProcess {
    fn drop(&mut self) {
        self.stdin.take();
        graceful_terminate(&mut self.child, GRACEFUL_SHUTDOWN_TIMEOUT);
        self.stdout_events.take();
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(drainer) = self.stderr_drainer.take() {
            let _ = drainer.join();
        }
    }
}

enum StdoutEvent {
    Line(String),
    ReadError,
    Eof,
}

fn read_stdout(stdout: impl io::Read, sender: &mpsc::SyncSender<StdoutEvent>) {
    let mut reader = BufReader::new(stdout);
    loop {
        match read_bounded_line(&mut reader) {
            Ok(Some(line)) => {
                if sender.send(StdoutEvent::Line(line)).is_err() {
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(StdoutEvent::Eof);
                return;
            }
            Err(_) => {
                let _ = sender.send(StdoutEvent::ReadError);
                return;
            }
        }
    }
}

fn read_bounded_line(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            return String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "JSONL is not UTF-8"));
        }

        if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            if bytes.len().saturating_add(newline) > MAX_JSONL_LINE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "JSONL line exceeds limit",
                ));
            }
            bytes.extend_from_slice(&buffer[..newline]);
            reader.consume(newline + 1);
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "JSONL is not UTF-8"));
        }

        if bytes.len().saturating_add(buffer.len()) > MAX_JSONL_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JSONL line exceeds limit",
            ));
        }
        bytes.extend_from_slice(buffer);
        let consumed = buffer.len();
        reader.consume(consumed);
    }
}

fn drain_stderr(mut stderr: impl io::Read) {
    let _ = io::copy(&mut stderr, &mut io::sink());
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn decode_response(line: &str, expected_id: u64) -> Result<Option<Value>, CodexUsageError> {
    let envelope: Value = serde_json::from_str(line).map_err(|_| CodexUsageError::Protocol)?;
    if !envelope.is_object() {
        return Err(CodexUsageError::Protocol);
    }
    if envelope.get("id").and_then(Value::as_u64) != Some(expected_id) {
        return Ok(None);
    }
    if let Some(error) = envelope.get("error") {
        return Err(classify_rpc_error(error));
    }
    envelope
        .get("result")
        .cloned()
        .map(Some)
        .ok_or(CodexUsageError::Protocol)
}

fn classify_rpc_error(error: &Value) -> CodexUsageError {
    let code = error.get("code").and_then(Value::as_i64);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if code == Some(-32601)
        || [
            "method not found",
            "not supported",
            "unsupported",
            "unimplemented",
        ]
        .iter()
        .any(|needle| message.contains(needle))
    {
        CodexUsageError::Unsupported
    } else if [
        "auth",
        "credential",
        "login required",
        "not logged in",
        "unauthorized",
    ]
    .iter()
    .any(|needle| message.contains(needle))
    {
        CodexUsageError::Authentication
    } else {
        CodexUsageError::Protocol
    }
}

fn graceful_terminate(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let _ = child.wait();
                return;
            }
            Ok(None) if deadline.is_some_and(|deadline| Instant::now() < deadline) => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => {
                terminate(child);
                return;
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireRateLimitsResult {
    #[serde(default)]
    rate_limits: Option<WireRateLimitSnapshot>,
    #[serde(default)]
    rate_limits_by_limit_id: Option<BTreeMap<String, WireRateLimitSnapshot>>,
    #[serde(default)]
    rate_limit_reset_credits: Option<WireResetCredits>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireRateLimitSnapshot {
    #[serde(default)]
    limit_id: Option<String>,
    #[serde(default)]
    limit_name: Option<String>,
    #[serde(default)]
    plan_type: Option<String>,
    #[serde(default)]
    rate_limit_reached_type: Option<String>,
    #[serde(default)]
    primary: Option<WireRateLimitWindow>,
    #[serde(default)]
    secondary: Option<WireRateLimitWindow>,
    #[serde(default)]
    credits: Option<WireCreditsSnapshot>,
    #[serde(default)]
    individual_limit: Option<WireSpendControlLimitSnapshot>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireRateLimitWindow {
    used_percent: u32,
    #[serde(default)]
    window_duration_mins: Option<u64>,
    #[serde(default)]
    resets_at: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireCreditsSnapshot {
    has_credits: bool,
    unlimited: bool,
    #[serde(default)]
    balance: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireSpendControlLimitSnapshot {
    limit: String,
    used: String,
    remaining_percent: u32,
    resets_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireResetCredits {
    available_count: u64,
    #[serde(default)]
    credits: Option<Vec<WireResetCreditDetail>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireResetCreditDetail {
    granted_at: i64,
    #[serde(default)]
    expires_at: Option<i64>,
    reset_type: String,
    status: String,
}

impl From<WireRateLimitSnapshot> for RateLimitSnapshot {
    fn from(wire: WireRateLimitSnapshot) -> Self {
        Self {
            limit_id: wire.limit_id,
            limit_name: wire.limit_name,
            plan_type: wire.plan_type,
            rate_limit_reached_type: wire.rate_limit_reached_type,
            primary: wire.primary.map(Into::into),
            secondary: wire.secondary.map(Into::into),
            credits: wire.credits.map(Into::into),
            individual_limit: wire.individual_limit.map(Into::into),
        }
    }
}

impl From<WireRateLimitWindow> for RateLimitWindow {
    fn from(wire: WireRateLimitWindow) -> Self {
        let remaining_percent = 100_u32.saturating_sub(wire.used_percent.min(100));
        Self {
            used_percent: wire.used_percent,
            remaining_percent,
            window_duration_mins: wire.window_duration_mins,
            resets_at: wire.resets_at,
        }
    }
}

impl From<WireCreditsSnapshot> for CreditsSnapshot {
    fn from(wire: WireCreditsSnapshot) -> Self {
        Self {
            has_credits: wire.has_credits,
            unlimited: wire.unlimited,
            balance: wire.balance,
        }
    }
}

impl From<WireSpendControlLimitSnapshot> for SpendControlLimitSnapshot {
    fn from(wire: WireSpendControlLimitSnapshot) -> Self {
        Self {
            limit: wire.limit,
            used: wire.used,
            remaining_percent: wire.remaining_percent,
            resets_at: wire.resets_at,
        }
    }
}

impl From<WireResetCredits> for ResetCredits {
    fn from(wire: WireResetCredits) -> Self {
        Self {
            available_count: wire.available_count,
            details: wire
                .credits
                .map(|credits| credits.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<WireResetCreditDetail> for ResetCreditDetail {
    fn from(wire: WireResetCreditDetail) -> Self {
        Self {
            granted_at: wire.granted_at,
            expires_at: wire.expires_at,
            reset_type: wire.reset_type,
            status: wire.status,
        }
    }
}

fn parse_rate_limits_result(result: Value) -> Result<CodexUsage, CodexUsageError> {
    let wire: WireRateLimitsResult =
        serde_json::from_value(result).map_err(|_| CodexUsageError::Protocol)?;
    if wire.rate_limits.is_none() && wire.rate_limits_by_limit_id.is_none() {
        return Err(CodexUsageError::Protocol);
    }

    Ok(CodexUsage {
        rate_limits: wire.rate_limits.map(Into::into),
        rate_limits_by_limit_id: wire
            .rate_limits_by_limit_id
            .unwrap_or_default()
            .into_iter()
            .map(|(limit_id, snapshot)| (limit_id, snapshot.into()))
            .collect(),
        reset_credits: wire.rate_limit_reset_credits.map(Into::into),
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io::{BufReader, Cursor};

    use serde_json::json;

    use super::*;

    #[test]
    fn managed_environment_filter_rejects_auth_config_and_future_overrides() {
        for name in [
            "OPENAI_API_KEY",
            "CODEX_ACCESS_TOKEN",
            "CoDeX_AcCeSs_ToKeN",
            "CODEX_AUTHAPI_BASE_URL",
            "CODEX_SQLITE_HOME",
            "CODEX_CONNECTORS_TOKEN",
            "CODEX_CLOUD_TASKS_BASE_URL",
            "CODEX_EXEC_SERVER_URL",
            "CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN",
            "CODEX_OSS_BASE_URL",
            "CODEX_CODE_MODE_HOST_PATH",
            "CODEX_TUI_RECORD_SESSION",
            "CODEX_TUI_SESSION_LOG_PATH",
            "CODEX_ROLLOUT_TRACE_ROOT",
            "CODEX_ANALYTICS_EVENTS_CAPTURE_FILE",
            "CODEX_TEST_FUTURE_AUTH_HOOK",
            "CoDeX_TeSt_Future_Auth_Hook",
            "CODEX_FUTURE_ENDPOINT_OVERRIDE",
            "CoDeX_FuTuRe_EnDpOiNt_OvErRiDe",
        ] {
            assert!(
                is_managed_environment_override(OsStr::new(name)),
                "{name} must not reach a managed Codex process"
            );
        }

        for name in [
            "CODEX_HOME",
            "CODEX_SANDBOX",
            "CODEX_THREAD_ID",
            "HTTPS_PROXY",
            "TERM",
        ] {
            assert!(
                !is_managed_environment_override(OsStr::new(name)),
                "{name} is outside the managed authentication denylist"
            );
        }
    }

    #[test]
    fn managed_commands_force_profile_local_cli_and_mcp_oauth_stores() {
        let command = managed_command(
            Path::new("/synthetic/codex"),
            Path::new("/synthetic/profile-home"),
        );
        let arguments = command
            .get_args()
            .map(OsStr::to_str)
            .collect::<Option<Vec<_>>>();

        assert_eq!(
            arguments,
            Some(vec![
                "-c",
                r#"cli_auth_credentials_store="file""#,
                "-c",
                r#"mcp_oauth_credentials_store="file""#,
            ])
        );
    }

    #[test]
    fn parses_full_usage_without_exposing_opaque_reset_credit_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let usage = parse_rate_limits_result(json!({
            "rateLimits": {
                "limitId": "codex",
                "limitName": "Codex",
                "planType": "plus",
                "rateLimitReachedType": null,
                "primary": {
                    "usedPercent": 73,
                    "windowDurationMins": 300,
                    "resetsAt": 1_800_000_000
                },
                "secondary": {
                    "usedPercent": 41,
                    "windowDurationMins": 10_080,
                    "resetsAt": 1_800_500_000
                },
                "credits": {
                    "hasCredits": true,
                    "unlimited": false,
                    "balance": "12.50"
                },
                "individualLimit": {
                    "limit": "100.00",
                    "used": "25.50",
                    "remainingPercent": 74,
                    "resetsAt": 1_801_000_000
                }
            },
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "primary": { "usedPercent": 73 },
                    "secondary": null,
                    "credits": null
                }
            },
            "rateLimitResetCredits": {
                "availableCount": 2,
                "credits": [{
                    "id": "opaque-credit-id",
                    "title": "backend title",
                    "description": "backend description",
                    "grantedAt": 1_700_000_000,
                    "expiresAt": 1_900_000_000,
                    "resetType": "codexRateLimits",
                    "status": "available"
                }]
            },
            "futureField": true
        }))?;

        let primary = usage
            .rate_limits
            .as_ref()
            .and_then(|snapshot| snapshot.primary.as_ref())
            .ok_or_else(|| std::io::Error::other("primary window must be present"))?;
        assert_eq!(primary.used_percent, 73);
        assert_eq!(primary.remaining_percent, 27);
        assert_eq!(primary.window_duration_mins, Some(300));
        assert_eq!(primary.resets_at, Some(1_800_000_000));
        assert_eq!(usage.rate_limits_by_limit_id.len(), 1);
        let individual_limit = usage
            .rate_limits
            .as_ref()
            .and_then(|snapshot| snapshot.individual_limit.as_ref())
            .ok_or_else(|| std::io::Error::other("individual limit must be present"))?;
        assert_eq!(individual_limit.limit, "100.00");
        assert_eq!(individual_limit.used, "25.50");
        assert_eq!(individual_limit.remaining_percent, 74);
        assert_eq!(individual_limit.resets_at, 1_801_000_000);

        let reset_credits = usage
            .reset_credits
            .as_ref()
            .ok_or_else(|| std::io::Error::other("reset credits must be present"))?;
        assert_eq!(reset_credits.available_count, 2);
        assert_eq!(reset_credits.details.as_ref().map(Vec::len), Some(1));

        let serialized = serde_json::to_string(&usage)?;
        for secret in ["opaque-credit-id", "backend title", "backend description"] {
            assert!(!serialized.contains(secret));
        }
        Ok(())
    }

    #[test]
    fn accepts_missing_optional_usage_fields() -> Result<(), Box<dyn std::error::Error>> {
        let usage = parse_rate_limits_result(json!({
            "rateLimits": {
                "primary": { "usedPercent": 0 }
            }
        }))?;

        let rate_limits = usage
            .rate_limits
            .as_ref()
            .ok_or_else(|| std::io::Error::other("legacy snapshot must be present"))?;
        let primary = rate_limits
            .primary
            .as_ref()
            .ok_or_else(|| std::io::Error::other("primary window must be present"))?;
        assert_eq!(primary.window_duration_mins, None);
        assert_eq!(primary.resets_at, None);
        assert_eq!(primary.remaining_percent, 100);
        assert!(rate_limits.secondary.is_none());
        assert!(rate_limits.credits.is_none());
        assert!(rate_limits.individual_limit.is_none());
        assert!(usage.rate_limits_by_limit_id.is_empty());
        assert!(usage.reset_credits.is_none());
        Ok(())
    }

    #[test]
    fn rejects_malformed_or_empty_usage_results() {
        let malformed = parse_rate_limits_result(json!({
            "rateLimits": {
                "primary": { "usedPercent": "73" }
            }
        }));
        let empty = parse_rate_limits_result(json!({ "futureField": true }));

        assert_eq!(malformed, Err(CodexUsageError::Protocol));
        assert_eq!(empty, Err(CodexUsageError::Protocol));
    }

    #[test]
    fn clamps_display_only_remaining_percentage_at_zero() -> Result<(), Box<dyn std::error::Error>>
    {
        let usage = parse_rate_limits_result(json!({
            "rateLimits": {
                "primary": { "usedPercent": 125 }
            }
        }))?;
        let remaining = usage
            .rate_limits
            .and_then(|snapshot| snapshot.primary)
            .map(|window| window.remaining_percent);

        assert_eq!(remaining, Some(0));
        Ok(())
    }

    #[test]
    fn classifies_rpc_failures_without_returning_provider_messages() {
        let unsupported = decode_response(
            r#"{"id":1,"error":{"code":-32601,"message":"raw method not found"}}"#,
            1,
        );
        let authentication = decode_response(
            r#"{"id":1,"error":{"code":-32600,"message":"raw authentication required"}}"#,
            1,
        );
        let protocol = decode_response(
            r#"{"id":1,"error":{"code":-32000,"message":"raw backend detail"}}"#,
            1,
        );

        assert_eq!(unsupported, Err(CodexUsageError::Unsupported));
        assert_eq!(authentication, Err(CodexUsageError::Authentication));
        assert_eq!(protocol, Err(CodexUsageError::Protocol));
        for error in [
            CodexUsageError::Unsupported,
            CodexUsageError::Authentication,
            CodexUsageError::Protocol,
        ] {
            assert!(!error.to_string().contains("raw"));
        }
    }

    #[test]
    fn ignores_notifications_and_rejects_malformed_protocol_lines() {
        let notification =
            decode_response(r#"{"method":"account/rateLimits/updated","params":{}}"#, 1);
        let malformed_json = decode_response("not-json", 1);
        let malformed_envelope = decode_response("[]", 1);

        assert_eq!(notification, Ok(None));
        assert_eq!(malformed_json, Err(CodexUsageError::Protocol));
        assert_eq!(malformed_envelope, Err(CodexUsageError::Protocol));
    }

    #[test]
    fn rejects_unvalidated_executable_names_before_spawning() {
        let result = read_account_usage(
            Path::new("codex"),
            Path::new("profile-home"),
            Path::new("neutral-working-directory"),
            Duration::from_secs(1),
        );

        assert_eq!(result, Err(CodexUsageError::Spawn));
    }

    #[test]
    fn reports_timeout_when_no_protocol_event_arrives() {
        let (_sender, events) = mpsc::sync_channel(1);
        let deadline = Instant::now();

        assert_eq!(
            receive_result_from(&events, RATE_LIMITS_REQUEST_ID, deadline),
            Err(CodexUsageError::Timeout)
        );
    }

    #[test]
    fn bounded_jsonl_reader_accepts_limit_and_rejects_oversized_lines()
    -> Result<(), Box<dyn std::error::Error>> {
        let exact = vec![b'a'; MAX_JSONL_LINE_BYTES];
        let mut exact_reader = BufReader::new(Cursor::new(exact));
        let exact_line = read_bounded_line(&mut exact_reader)?;
        assert_eq!(
            exact_line.as_ref().map(String::len),
            Some(MAX_JSONL_LINE_BYTES)
        );

        let mut with_newline = vec![b'b'; MAX_JSONL_LINE_BYTES];
        with_newline.push(b'\n');
        let mut newline_reader = BufReader::new(Cursor::new(with_newline));
        let newline_line = read_bounded_line(&mut newline_reader)?;
        assert_eq!(
            newline_line.as_ref().map(String::len),
            Some(MAX_JSONL_LINE_BYTES)
        );

        let oversized = vec![b'c'; MAX_JSONL_LINE_BYTES + 1];
        let mut oversized_reader = BufReader::new(Cursor::new(oversized));
        let error = read_bounded_line(&mut oversized_reader)
            .err()
            .ok_or_else(|| io::Error::other("oversized JSONL must fail"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }
}
