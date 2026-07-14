//! Read-only Codex account usage through the official app-server protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
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
const MAX_ROLLOUT_BYTES: usize = 64 * 1024 * 1024;
const THREAD_PAGE_SIZE: u32 = 100;
const MAX_THREAD_PAGES_PER_STATE: usize = 8;
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);
const APP_SERVER_CLIENT_NAME: &str = "calcifer";

pub(crate) const CODEX_STATUS_PROTOCOL: &str = "account/rateLimits/read";
pub(crate) const SUPPORTED_CODEX_STATUS_VERSIONS: &[&str] = &["0.144.4"];
/// Minimal, redacted metadata for one persisted root CLI thread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexThreadMetadata {
    pub(crate) thread_id: String,
    pub(crate) canonical_cwd: PathBuf,
    pub(crate) cli_version: String,
    pub(crate) updated_at: i64,
    pub(crate) recency_at: Option<i64>,
    pub(crate) archived: bool,
    rollout_path: PathBuf,
}

/// A complete bounded inventory from active and archived thread stores.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexThreadInventory {
    pub(crate) codex_version: String,
    pub(crate) threads: Vec<CodexThreadMetadata>,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexThreadRead {
    pub(crate) codex_version: String,
    pub(crate) metadata: CodexThreadMetadata,
    pub(crate) lifecycle: CodexThreadLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexThreadLifecycle {
    Clean,
    Interrupted,
    UnknownCrash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexThreadError {
    UnsupportedVersion,
    Protocol,
    CwdMismatch,
    Authentication,
    Timeout,
    Transport,
    Provider,
    Spawn,
    Missing,
    Archived,
    SessionSchema,
}

impl fmt::Display for CodexThreadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "the installed Codex version is not supported",
            Self::Protocol => "Codex returned invalid thread metadata",
            Self::CwdMismatch => "the Codex thread belongs to another working directory",
            Self::Authentication => "the Codex profile is not authenticated",
            Self::Timeout => "the Codex thread metadata read timed out",
            Self::Transport => "Codex thread metadata transport ended unexpectedly",
            Self::Provider => "Codex rejected the thread metadata request",
            Self::Spawn => "the Codex app-server could not be started",
            Self::Missing => "the Codex thread rollout is missing",
            Self::Archived => "the Codex thread is archived",
            Self::SessionSchema => "the Codex rollout schema is unsupported",
        })
    }
}

impl std::error::Error for CodexThreadError {}

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

/// A usage snapshot admitted by Calcifer's version and initialize-schema gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexUsageObservation {
    pub codex_version: String,
    pub usage: CodexUsage,
}

/// Whether the installed App Server contract was verified for this read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexCompatibilityStatus {
    Compatible,
    Incompatible,
    Unverified,
}

impl CodexCompatibilityStatus {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Incompatible => "incompatible",
            Self::Unverified => "unverified",
        }
    }
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
    Transport,
    Provider,
    Spawn,
}

impl fmt::Display for CodexUsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unsupported => "the Codex app-server does not support account usage reads",
            Self::Protocol => "the Codex app-server returned an invalid protocol response",
            Self::Authentication => "the Codex profile is not authenticated",
            Self::Timeout => "the Codex app-server usage read timed out",
            Self::Transport => "communication with the Codex app-server ended unexpectedly",
            Self::Provider => "the Codex app-server returned an unrecognized provider error",
            Self::Spawn => "the Codex app-server could not be started",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CodexUsageError {}

/// A redacted read failure with any compatibility evidence collected first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexUsageFailure {
    kind: CodexUsageError,
    codex_version: Option<String>,
    compatibility: CodexCompatibilityStatus,
}

impl CodexUsageFailure {
    fn before_gate(kind: CodexUsageError) -> Self {
        let compatibility = match kind {
            CodexUsageError::Unsupported | CodexUsageError::Protocol => {
                CodexCompatibilityStatus::Incompatible
            }
            CodexUsageError::Authentication
            | CodexUsageError::Timeout
            | CodexUsageError::Transport
            | CodexUsageError::Provider
            | CodexUsageError::Spawn => CodexCompatibilityStatus::Unverified,
        };
        Self {
            kind,
            codex_version: None,
            compatibility,
        }
    }

    fn incompatible(kind: CodexUsageError, codex_version: Option<String>) -> Self {
        Self {
            kind,
            codex_version,
            compatibility: CodexCompatibilityStatus::Incompatible,
        }
    }

    fn after_gate(kind: CodexUsageError, codex_version: &str) -> Self {
        let compatibility = match kind {
            CodexUsageError::Authentication => CodexCompatibilityStatus::Compatible,
            CodexUsageError::Unsupported | CodexUsageError::Protocol => {
                CodexCompatibilityStatus::Incompatible
            }
            CodexUsageError::Timeout
            | CodexUsageError::Transport
            | CodexUsageError::Provider
            | CodexUsageError::Spawn => CodexCompatibilityStatus::Unverified,
        };
        Self {
            kind,
            codex_version: Some(codex_version.to_owned()),
            compatibility,
        }
    }

    pub(crate) const fn kind(&self) -> CodexUsageError {
        self.kind
    }

    pub(crate) fn codex_version(&self) -> Option<&str> {
        self.codex_version.as_deref()
    }

    pub(crate) const fn compatibility(&self) -> CodexCompatibilityStatus {
        self.compatibility
    }
}

impl fmt::Display for CodexUsageFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for CodexUsageFailure {}

/// Reads one account usage snapshot from the official Codex app-server.
pub fn read_account_usage(
    codex_executable: &Path,
    codex_home: &Path,
    working_directory: &Path,
    timeout: Duration,
) -> Result<CodexUsageObservation, CodexUsageFailure> {
    if !codex_executable.is_absolute() {
        return Err(CodexUsageFailure::before_gate(CodexUsageError::Spawn));
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CodexUsageFailure::before_gate(CodexUsageError::Timeout))?;
    let mut process = AppServerProcess::spawn(codex_executable, codex_home, working_directory)
        .map_err(CodexUsageFailure::before_gate)?;

    process
        .send(&json!({
            "id": INITIALIZE_REQUEST_ID,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": APP_SERVER_CLIENT_NAME,
                    "title": "Calcifer",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": {
                    "experimentalApi": false
                }
            }
        }))
        .map_err(CodexUsageFailure::before_gate)?;
    let initialize_result = process
        .receive_result(INITIALIZE_REQUEST_ID, deadline)
        .map_err(CodexUsageFailure::before_gate)?;
    let codex_version = validate_initialize_result(initialize_result, codex_home)
        .map_err(|error| CodexUsageFailure::incompatible(error.kind, error.codex_version))?;

    process
        .send(&json!({ "method": "initialized", "params": {} }))
        .map_err(|error| CodexUsageFailure::after_gate(error, &codex_version))?;
    process
        .send(&json!({
            "id": RATE_LIMITS_REQUEST_ID,
            "method": CODEX_STATUS_PROTOCOL,
            "params": null
        }))
        .map_err(|error| CodexUsageFailure::after_gate(error, &codex_version))?;

    let result = process
        .receive_result(RATE_LIMITS_REQUEST_ID, deadline)
        .map_err(|error| CodexUsageFailure::after_gate(error, &codex_version))?;
    let usage = parse_rate_limits_result(result)
        .map_err(|error| CodexUsageFailure::after_gate(error, &codex_version))?;
    Ok(CodexUsageObservation {
        codex_version,
        usage,
    })
}

/// Reads a bounded active-and-archived inventory for one exact workspace.
///
/// The returned projection intentionally drops preview, model, provider, turn,
/// and tool fields before it crosses the adapter boundary.
pub(crate) fn read_thread_inventory(
    codex_executable: &Path,
    codex_home: &Path,
    neutral_working_directory: &Path,
    canonical_cwd: &Path,
    timeout: Duration,
) -> Result<CodexThreadInventory, CodexThreadError> {
    let canonical_cwd = fs::canonicalize(canonical_cwd).map_err(|_| CodexThreadError::Protocol)?;
    if !canonical_cwd.is_dir() {
        return Err(CodexThreadError::Protocol);
    }
    let canonical_cwd_string = canonical_cwd
        .to_str()
        .ok_or(CodexThreadError::Protocol)?
        .to_owned();
    let deadline = thread_deadline(codex_executable, timeout)?;
    let (mut process, codex_version) = initialize_thread_client(
        codex_executable,
        codex_home,
        neutral_working_directory,
        deadline,
    )?;

    let mut threads = Vec::new();
    let mut complete = true;
    let mut request_id = 1_u64;
    for archived in [false, true] {
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        for page_index in 0..MAX_THREAD_PAGES_PER_STATE {
            process
                .send(&json!({
                    "id": request_id,
                    "method": "thread/list",
                    "params": {
                        "cursor": cursor,
                        "limit": THREAD_PAGE_SIZE,
                        "sortKey": "updated_at",
                        "sortDirection": "asc",
                        "sourceKinds": ["cli"],
                        "archived": archived,
                        "cwd": canonical_cwd_string,
                        "useStateDbOnly": false
                    }
                }))
                .map_err(map_thread_transport)?;
            let result = process.receive_thread_result(request_id, deadline)?;
            request_id = request_id
                .checked_add(1)
                .ok_or(CodexThreadError::Protocol)?;
            let page: WireThreadListResponse =
                serde_json::from_value(result).map_err(|_| CodexThreadError::Protocol)?;
            for wire in page.data {
                let metadata = validate_thread_projection(
                    wire,
                    &canonical_cwd,
                    codex_home,
                    &codex_version,
                    Some(archived),
                )?;
                if threads
                    .iter()
                    .any(|existing: &CodexThreadMetadata| existing.thread_id == metadata.thread_id)
                {
                    return Err(CodexThreadError::Protocol);
                }
                threads.push(metadata);
            }
            match page.next_cursor {
                None => break,
                Some(_) if page_index + 1 == MAX_THREAD_PAGES_PER_STATE => {
                    complete = false;
                    break;
                }
                Some(next_cursor) => {
                    if next_cursor.is_empty() || !seen_cursors.insert(next_cursor.clone()) {
                        return Err(CodexThreadError::Protocol);
                    }
                    cursor = Some(next_cursor);
                }
            }
        }
    }
    threads.sort_by(|left, right| left.thread_id.cmp(&right.thread_id));
    Ok(CodexThreadInventory {
        codex_version,
        threads,
        complete,
    })
}

/// Reads and validates one exact thread without loading turns.
pub(crate) fn read_thread_metadata(
    codex_executable: &Path,
    codex_home: &Path,
    neutral_working_directory: &Path,
    canonical_cwd: &Path,
    thread_id: &str,
    timeout: Duration,
) -> Result<CodexThreadRead, CodexThreadError> {
    validate_canonical_uuid(thread_id)?;
    let canonical_cwd = fs::canonicalize(canonical_cwd).map_err(|_| CodexThreadError::Protocol)?;
    if !canonical_cwd.is_dir() {
        return Err(CodexThreadError::Protocol);
    }
    let deadline = thread_deadline(codex_executable, timeout)?;
    let (mut process, codex_version) = initialize_thread_client(
        codex_executable,
        codex_home,
        neutral_working_directory,
        deadline,
    )?;
    process
        .send(&json!({
            "id": 1,
            "method": "thread/read",
            "params": {
                "threadId": thread_id,
                "includeTurns": false
            }
        }))
        .map_err(map_thread_transport)?;
    let result = process.receive_thread_result(1, deadline)?;
    let response: WireThreadReadResponse =
        serde_json::from_value(result).map_err(|_| CodexThreadError::Protocol)?;
    let metadata = validate_thread_projection(
        response.thread,
        &canonical_cwd,
        codex_home,
        &codex_version,
        None,
    )?;
    if metadata.thread_id != thread_id {
        return Err(CodexThreadError::Protocol);
    }
    if metadata.archived {
        return Err(CodexThreadError::Archived);
    }
    let lifecycle = inspect_rollout_lifecycle(&metadata, &canonical_cwd)?;
    Ok(CodexThreadRead {
        codex_version,
        metadata,
        lifecycle,
    })
}

fn thread_deadline(
    codex_executable: &Path,
    timeout: Duration,
) -> Result<Instant, CodexThreadError> {
    if !codex_executable.is_absolute() {
        return Err(CodexThreadError::Spawn);
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(CodexThreadError::Timeout)
}

fn initialize_thread_client(
    codex_executable: &Path,
    codex_home: &Path,
    neutral_working_directory: &Path,
    deadline: Instant,
) -> Result<(AppServerProcess, String), CodexThreadError> {
    let mut process =
        AppServerProcess::spawn(codex_executable, codex_home, neutral_working_directory)
            .map_err(map_thread_transport)?;
    process
        .send(&json!({
            "id": INITIALIZE_REQUEST_ID,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": APP_SERVER_CLIENT_NAME,
                    "title": "Calcifer",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": { "experimentalApi": false }
            }
        }))
        .map_err(map_thread_transport)?;
    let initialize_result = process
        .receive_result(INITIALIZE_REQUEST_ID, deadline)
        .map_err(map_thread_transport)?;
    let codex_version =
        validate_initialize_result(initialize_result, codex_home).map_err(|error| {
            match error.reason {
                InitializeFailureReason::UnsupportedVersion => CodexThreadError::UnsupportedVersion,
                InitializeFailureReason::Malformed | InitializeFailureReason::HomeMismatch => {
                    CodexThreadError::Protocol
                }
            }
        })?;
    process
        .send(&json!({ "method": "initialized", "params": {} }))
        .map_err(map_thread_transport)?;
    Ok((process, codex_version))
}

fn map_thread_transport(error: CodexUsageError) -> CodexThreadError {
    match error {
        CodexUsageError::Unsupported => CodexThreadError::UnsupportedVersion,
        CodexUsageError::Protocol => CodexThreadError::Protocol,
        CodexUsageError::Authentication => CodexThreadError::Authentication,
        CodexUsageError::Timeout => CodexThreadError::Timeout,
        CodexUsageError::Transport => CodexThreadError::Transport,
        CodexUsageError::Provider => CodexThreadError::Provider,
        CodexUsageError::Spawn => CodexThreadError::Spawn,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireThreadListResponse {
    data: Vec<WireThread>,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireThreadReadResponse {
    thread: WireThread,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireThread {
    id: String,
    parent_thread_id: Option<String>,
    ephemeral: bool,
    updated_at: i64,
    recency_at: Option<i64>,
    cwd: PathBuf,
    cli_version: String,
    source: Value,
    path: Option<PathBuf>,
}

fn validate_thread_projection(
    wire: WireThread,
    expected_cwd: &Path,
    codex_home: &Path,
    expected_version: &str,
    expected_archived: Option<bool>,
) -> Result<CodexThreadMetadata, CodexThreadError> {
    validate_canonical_uuid(&wire.id)?;
    if wire.parent_thread_id.is_some()
        || wire.ephemeral
        || wire.updated_at < 0
        || wire.recency_at.is_some_and(|timestamp| timestamp < 0)
        || wire.cli_version != expected_version
        || wire.source.as_str() != Some("cli")
    {
        return Err(CodexThreadError::Protocol);
    }
    let canonical_cwd = fs::canonicalize(&wire.cwd).map_err(|_| CodexThreadError::CwdMismatch)?;
    if canonical_cwd != expected_cwd {
        return Err(CodexThreadError::CwdMismatch);
    }
    let rollout_path = wire.path.ok_or(CodexThreadError::Missing)?;
    let archived = validate_rollout_path(codex_home, &rollout_path)?;
    if expected_archived.is_some_and(|expected| expected != archived) {
        return Err(CodexThreadError::Protocol);
    }
    Ok(CodexThreadMetadata {
        thread_id: wire.id,
        canonical_cwd,
        cli_version: wire.cli_version,
        updated_at: wire.updated_at,
        recency_at: wire.recency_at,
        archived,
        rollout_path,
    })
}

fn validate_canonical_uuid(value: &str) -> Result<(), CodexThreadError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| CodexThreadError::Protocol)?;
    if parsed.to_string() != value {
        return Err(CodexThreadError::Protocol);
    }
    Ok(())
}

fn validate_rollout_path(codex_home: &Path, path: &Path) -> Result<bool, CodexThreadError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if path.extension().and_then(|extension| extension.to_str()) != Some("jsonl") {
            return Err(CodexThreadError::SessionSchema);
        }
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CodexThreadError::Missing
            } else {
                CodexThreadError::SessionSchema
            }
        })?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() > MAX_ROLLOUT_BYTES as u64
        {
            return Err(CodexThreadError::SessionSchema);
        }
        let canonical_home =
            fs::canonicalize(codex_home).map_err(|_| CodexThreadError::SessionSchema)?;
        let canonical_path = fs::canonicalize(path).map_err(|_| CodexThreadError::Missing)?;
        let active_root = canonical_home.join("sessions");
        let archived_root = canonical_home.join("archived_sessions");
        if canonical_path.starts_with(&active_root) {
            Ok(false)
        } else if canonical_path.starts_with(&archived_root) {
            Ok(true)
        } else {
            Err(CodexThreadError::SessionSchema)
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (codex_home, path);
        Err(CodexThreadError::SessionSchema)
    }
}

fn inspect_rollout_lifecycle(
    metadata: &CodexThreadMetadata,
    expected_cwd: &Path,
) -> Result<CodexThreadLifecycle, CodexThreadError> {
    let file = fs::File::open(&metadata.rollout_path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            CodexThreadError::Missing
        } else {
            CodexThreadError::SessionSchema
        }
    })?;
    let mut reader = BufReader::new(file);
    let first = read_bounded_line(&mut reader)
        .map_err(|_| CodexThreadError::SessionSchema)?
        .ok_or(CodexThreadError::SessionSchema)?;
    validate_session_meta_line(&first, metadata, expected_cwd)?;

    let mut lifecycle = CodexThreadLifecycle::Clean;
    while let Some(line) =
        read_bounded_line(&mut reader).map_err(|_| CodexThreadError::SessionSchema)?
    {
        let value: Value =
            serde_json::from_str(&line).map_err(|_| CodexThreadError::SessionSchema)?;
        let object = value.as_object().ok_or(CodexThreadError::SessionSchema)?;
        match object.get("type").and_then(Value::as_str) {
            Some("session_meta") => validate_session_meta_value(&value, metadata, expected_cwd)?,
            Some("event_msg") => {
                let event_type = object
                    .get("payload")
                    .and_then(Value::as_object)
                    .and_then(|payload| payload.get("type"))
                    .and_then(Value::as_str);
                lifecycle = match event_type {
                    Some("task_started" | "turn_started") => CodexThreadLifecycle::UnknownCrash,
                    Some("task_complete" | "turn_complete") => CodexThreadLifecycle::Clean,
                    Some("turn_aborted") => CodexThreadLifecycle::Interrupted,
                    _ => lifecycle,
                };
            }
            Some(_) => {}
            None => return Err(CodexThreadError::SessionSchema),
        }
    }
    Ok(lifecycle)
}

fn validate_session_meta_line(
    line: &str,
    metadata: &CodexThreadMetadata,
    expected_cwd: &Path,
) -> Result<(), CodexThreadError> {
    let value: Value = serde_json::from_str(line).map_err(|_| CodexThreadError::SessionSchema)?;
    validate_session_meta_value(&value, metadata, expected_cwd)
}

fn validate_session_meta_value(
    value: &Value,
    metadata: &CodexThreadMetadata,
    expected_cwd: &Path,
) -> Result<(), CodexThreadError> {
    let object = value.as_object().ok_or(CodexThreadError::SessionSchema)?;
    if object.get("type").and_then(Value::as_str) != Some("session_meta") {
        return Err(CodexThreadError::SessionSchema);
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(CodexThreadError::SessionSchema)?;
    let id = payload
        .get("id")
        .and_then(Value::as_str)
        .ok_or(CodexThreadError::SessionSchema)?;
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .ok_or(CodexThreadError::SessionSchema)?;
    let cli_version = payload
        .get("cli_version")
        .and_then(Value::as_str)
        .ok_or(CodexThreadError::SessionSchema)?;
    let source = payload
        .get("source")
        .and_then(Value::as_str)
        .ok_or(CodexThreadError::SessionSchema)?;
    let canonical_cwd = fs::canonicalize(cwd).map_err(|_| CodexThreadError::SessionSchema)?;
    if id != metadata.thread_id
        || canonical_cwd != expected_cwd
        || cli_version != metadata.cli_version
        || source != "cli"
        || payload
            .get("parent_thread_id")
            .is_some_and(|parent| !parent.is_null())
    {
        return Err(CodexThreadError::SessionSchema);
    }
    Ok(())
}

const INITIALIZE_REQUEST_ID: u64 = 0;
const RATE_LIMITS_REQUEST_ID: u64 = 1;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireInitializeResult {
    user_agent: String,
    codex_home: String,
    platform_family: String,
    platform_os: String,
}

#[derive(Debug)]
struct InitializeCompatibilityError {
    kind: CodexUsageError,
    codex_version: Option<String>,
    reason: InitializeFailureReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitializeFailureReason {
    Malformed,
    UnsupportedVersion,
    HomeMismatch,
}

impl fmt::Display for InitializeCompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the Codex initialize compatibility check failed")
    }
}

impl std::error::Error for InitializeCompatibilityError {}

fn validate_initialize_result(
    result: Value,
    selected_codex_home: &Path,
) -> Result<String, InitializeCompatibilityError> {
    let wire: WireInitializeResult =
        serde_json::from_value(result).map_err(|_| InitializeCompatibilityError {
            kind: CodexUsageError::Protocol,
            codex_version: None,
            reason: InitializeFailureReason::Malformed,
        })?;
    let codex_version = parse_codex_version(&wire.user_agent);
    let unsupported = || InitializeCompatibilityError {
        kind: CodexUsageError::Unsupported,
        codex_version: codex_version.clone(),
        reason: InitializeFailureReason::HomeMismatch,
    };
    let malformed = || InitializeCompatibilityError {
        kind: CodexUsageError::Protocol,
        codex_version: codex_version.clone(),
        reason: InitializeFailureReason::Malformed,
    };

    if wire.platform_family.is_empty() || wire.platform_os.is_empty() {
        return Err(malformed());
    }

    let reported_home = Path::new(&wire.codex_home);
    if !reported_home.is_absolute() {
        return Err(unsupported());
    }
    let reported_home = fs::canonicalize(reported_home).map_err(|_| unsupported())?;
    let selected_codex_home = fs::canonicalize(selected_codex_home).map_err(|_| unsupported())?;
    if reported_home != selected_codex_home {
        return Err(unsupported());
    }

    let codex_version = match codex_version.as_deref() {
        Some(codex_version) => codex_version.to_owned(),
        None => return Err(unsupported()),
    };
    if !SUPPORTED_CODEX_STATUS_VERSIONS.contains(&codex_version.as_str()) {
        return Err(InitializeCompatibilityError {
            kind: CodexUsageError::Unsupported,
            codex_version: Some(codex_version),
            reason: InitializeFailureReason::UnsupportedVersion,
        });
    }
    Ok(codex_version)
}

fn parse_codex_version(user_agent: &str) -> Option<String> {
    let token = user_agent.split_ascii_whitespace().next()?;
    let version = token
        .strip_prefix(APP_SERVER_CLIENT_NAME)?
        .strip_prefix('/')?;
    if version.is_empty() || version.len() > 32 {
        return None;
    }

    let mut components = version.split('.');
    let major = parse_version_component(components.next()?)?;
    let minor = parse_version_component(components.next()?)?;
    let patch = parse_version_component(components.next()?)?;
    if components.next().is_some() {
        return None;
    }
    let normalized = format!("{major}.{minor}.{patch}");
    (normalized == version).then_some(normalized)
}

fn parse_version_component(component: &str) -> Option<u32> {
    if component.is_empty()
        || component.len() > 10
        || !component.bytes().all(|byte| byte.is_ascii_digit())
        || (component.len() > 1 && component.starts_with('0'))
    {
        return None;
    }
    component.parse().ok()
}

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
        let stdin = self.stdin.as_mut().ok_or(CodexUsageError::Transport)?;
        write_json_line(stdin, message)
    }

    fn receive_result(
        &self,
        expected_id: u64,
        deadline: Instant,
    ) -> Result<Value, CodexUsageError> {
        let events = self
            .stdout_events
            .as_ref()
            .ok_or(CodexUsageError::Transport)?;
        receive_result_from(events, expected_id, deadline)
    }

    fn receive_thread_result(
        &self,
        expected_id: u64,
        deadline: Instant,
    ) -> Result<Value, CodexThreadError> {
        let events = self
            .stdout_events
            .as_ref()
            .ok_or(CodexThreadError::Transport)?;
        receive_thread_result_from(events, expected_id, deadline)
    }
}

fn write_json_line(writer: &mut impl Write, message: &Value) -> Result<(), CodexUsageError> {
    serde_json::to_writer(&mut *writer, message).map_err(|_| CodexUsageError::Transport)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|_| CodexUsageError::Transport)
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
            Err(RecvTimeoutError::Disconnected) => return Err(CodexUsageError::Transport),
        };
        let line = match event {
            StdoutEvent::Line(line) => line,
            StdoutEvent::ProtocolError => return Err(CodexUsageError::Protocol),
            StdoutEvent::TransportError | StdoutEvent::Eof => {
                return Err(CodexUsageError::Transport);
            }
        };
        if let Some(result) = decode_response(&line, expected_id)? {
            return Ok(result);
        }
    }
}

fn receive_thread_result_from(
    events: &Receiver<StdoutEvent>,
    expected_id: u64,
    deadline: Instant,
) -> Result<Value, CodexThreadError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(CodexThreadError::Timeout)?;
        let event = match events.recv_timeout(remaining) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => return Err(CodexThreadError::Timeout),
            Err(RecvTimeoutError::Disconnected) => return Err(CodexThreadError::Transport),
        };
        let line = match event {
            StdoutEvent::Line(line) => line,
            StdoutEvent::ProtocolError => return Err(CodexThreadError::Protocol),
            StdoutEvent::TransportError | StdoutEvent::Eof => {
                return Err(CodexThreadError::Transport);
            }
        };
        if let Some(result) = decode_thread_response(&line, expected_id)? {
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
    ProtocolError,
    TransportError,
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
            Err(error) => {
                let event = if error.kind() == io::ErrorKind::InvalidData {
                    StdoutEvent::ProtocolError
                } else {
                    StdoutEvent::TransportError
                };
                let _ = sender.send(event);
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
    match (envelope.get("result"), envelope.get("error")) {
        (Some(result), None) => Ok(Some(result.clone())),
        (None, Some(error)) => Err(classify_rpc_error(error)),
        _ => Err(CodexUsageError::Protocol),
    }
}

fn decode_thread_response(line: &str, expected_id: u64) -> Result<Option<Value>, CodexThreadError> {
    let envelope: Value = serde_json::from_str(line).map_err(|_| CodexThreadError::Protocol)?;
    if !envelope.is_object() {
        return Err(CodexThreadError::Protocol);
    }
    if envelope.get("id").and_then(Value::as_u64) != Some(expected_id) {
        return Ok(None);
    }
    match (envelope.get("result"), envelope.get("error")) {
        (Some(result), None) => Ok(Some(result.clone())),
        (None, Some(error)) => Err(classify_thread_rpc_error(error)),
        _ => Err(CodexThreadError::Protocol),
    }
}

fn classify_thread_rpc_error(error: &Value) -> CodexThreadError {
    let Some(code) = error.get("code").and_then(Value::as_i64) else {
        return CodexThreadError::Protocol;
    };
    let Some(message) = error.get("message").and_then(Value::as_str) else {
        return CodexThreadError::Protocol;
    };
    let message = message.to_ascii_lowercase();
    if message.contains("archived") {
        CodexThreadError::Archived
    } else if ["not loaded", "not found", "no rollout"]
        .iter()
        .any(|needle| message.contains(needle))
    {
        CodexThreadError::Missing
    } else if code == -32601
        || ["method not found", "not supported", "unsupported"]
            .iter()
            .any(|needle| message.contains(needle))
    {
        CodexThreadError::Protocol
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
        CodexThreadError::Authentication
    } else {
        CodexThreadError::Provider
    }
}

fn classify_rpc_error(error: &Value) -> CodexUsageError {
    let Some(code) = error.get("code").and_then(Value::as_i64) else {
        return CodexUsageError::Protocol;
    };
    let Some(message) = error.get("message").and_then(Value::as_str) else {
        return CodexUsageError::Protocol;
    };
    let message = message.to_ascii_lowercase();

    if code == -32601
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
        CodexUsageError::Provider
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
    rate_limits: WireRateLimitSnapshot,
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

    Ok(CodexUsage {
        rate_limits: Some(wire.rate_limits.into()),
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
    use std::io::{BufReader, Cursor, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::*;

    #[test]
    fn managed_command_forces_profile_local_auth_stores() {
        let command = managed_command(
            Path::new("/synthetic/codex"),
            Path::new("/synthetic/profile"),
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
    fn initialize_gate_accepts_only_the_tested_version_and_selected_home()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sandbox = std::env::temp_dir().join(format!(
            "calcifer-codex-compatibility-{}-{nonce}",
            std::process::id()
        ));
        let selected_home = sandbox.join("selected-home");
        let other_home = sandbox.join("other-home");
        std::fs::create_dir_all(&selected_home)?;
        std::fs::create_dir_all(&other_home)?;

        let supported = validate_initialize_result(
            json!({
                "userAgent": "calcifer/0.144.4 (synthetic test)",
                "platformFamily": "unix",
                "platformOs": "test",
                "codexHome": selected_home
            }),
            &selected_home,
        )?;
        assert_eq!(supported, "0.144.4");

        let alias_parent = sandbox.join("alias-parent");
        std::fs::create_dir(&alias_parent)?;
        let canonical_alias = alias_parent.join("..").join("selected-home");
        let supported_through_alias = validate_initialize_result(
            json!({
                "userAgent": "calcifer/0.144.4 (synthetic test)",
                "platformFamily": "unix",
                "platformOs": "test",
                "codexHome": canonical_alias
            }),
            &selected_home,
        )?;
        assert_eq!(supported_through_alias, "0.144.4");

        let unsupported = validate_initialize_result(
            json!({
                "userAgent": "calcifer/0.145.0 (synthetic test)",
                "platformFamily": "unix",
                "platformOs": "test",
                "codexHome": selected_home
            }),
            &selected_home,
        )
        .err()
        .ok_or_else(|| io::Error::other("untested version must fail"))?;
        assert_eq!(unsupported.kind, CodexUsageError::Unsupported);
        assert_eq!(unsupported.codex_version.as_deref(), Some("0.145.0"));

        let wrong_home = validate_initialize_result(
            json!({
                "userAgent": "calcifer/0.144.4 (synthetic test)",
                "platformFamily": "unix",
                "platformOs": "test",
                "codexHome": other_home
            }),
            &selected_home,
        )
        .err()
        .ok_or_else(|| io::Error::other("wrong managed home must fail"))?;
        assert_eq!(wrong_home.kind, CodexUsageError::Unsupported);
        assert_eq!(wrong_home.codex_version.as_deref(), Some("0.144.4"));

        std::fs::remove_dir_all(sandbox)?;
        Ok(())
    }

    #[test]
    fn initialize_gate_rejects_malformed_schema_without_echoing_raw_user_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sandbox = std::env::temp_dir().join(format!(
            "calcifer-codex-initialize-schema-{}-{nonce}",
            std::process::id()
        ));
        let selected_home = sandbox.join("selected-home");
        std::fs::create_dir_all(&selected_home)?;

        for (malformed, expected_kind) in [
            (
                json!({
                    "userAgent": "calcifer/0.144.4 secret@example.test",
                    "platformFamily": "unix",
                    "codexHome": selected_home
                }),
                CodexUsageError::Protocol,
            ),
            (
                json!({
                    "userAgent": "calcifer/not-a-version secret@example.test",
                    "platformFamily": "unix",
                    "platformOs": "test",
                    "codexHome": selected_home
                }),
                CodexUsageError::Unsupported,
            ),
            (
                json!({
                    "userAgent": "calcifer/0.144.4 secret@example.test",
                    "platformFamily": "unix",
                    "platformOs": "test",
                    "codexHome": "relative/home"
                }),
                CodexUsageError::Unsupported,
            ),
        ] {
            let error = validate_initialize_result(malformed, &selected_home)
                .err()
                .ok_or_else(|| io::Error::other("malformed initialize result must fail"))?;
            assert_eq!(error.kind, expected_kind);
            assert!(!format!("{error:?}").contains("secret@example.test"));
        }

        std::fs::remove_dir_all(sandbox)?;
        Ok(())
    }

    #[test]
    fn compatibility_metadata_distinguishes_contract_drift_from_unverified_failures() {
        for kind in [CodexUsageError::Unsupported, CodexUsageError::Protocol] {
            let failure = CodexUsageFailure::after_gate(kind, "0.144.4");
            assert_eq!(
                failure.compatibility(),
                CodexCompatibilityStatus::Incompatible
            );
            assert_eq!(failure.codex_version(), Some("0.144.4"));
        }

        let authentication =
            CodexUsageFailure::after_gate(CodexUsageError::Authentication, "0.144.4");
        assert_eq!(
            authentication.compatibility(),
            CodexCompatibilityStatus::Compatible
        );

        let timeout = CodexUsageFailure::after_gate(CodexUsageError::Timeout, "0.144.4");
        assert_eq!(
            timeout.compatibility(),
            CodexCompatibilityStatus::Unverified
        );

        let spawn = CodexUsageFailure::before_gate(CodexUsageError::Spawn);
        assert_eq!(spawn.compatibility(), CodexCompatibilityStatus::Unverified);
        assert!(spawn.codex_version().is_none());

        for kind in [CodexUsageError::Transport, CodexUsageError::Provider] {
            let failure = CodexUsageFailure::before_gate(kind);
            assert_eq!(
                failure.compatibility(),
                CodexCompatibilityStatus::Unverified
            );
            assert!(failure.codex_version().is_none());

            let failure = CodexUsageFailure::after_gate(kind, "0.144.4");
            assert_eq!(
                failure.compatibility(),
                CodexCompatibilityStatus::Unverified
            );
            assert_eq!(failure.codex_version(), Some("0.144.4"));
        }
    }

    #[test]
    fn version_parser_rejects_spoofed_or_unbounded_releases() {
        assert_eq!(
            parse_codex_version("calcifer/0.144.4 (synthetic test)"),
            Some("0.144.4".to_owned())
        );

        for user_agent in [
            "codex-cli/0.144.4",
            "calcifer/00.144.4",
            "calcifer/0.0144.4",
            "calcifer/0.144.04",
            "calcifer/0.144.4-beta.1",
            "calcifer/0.144.4+build",
            "calcifer/0.144.4.1",
            "calcifer/4294967296.144.4",
            "calcifer/12345678901.144.4",
            "calcifer/0.144.4secret@example.test",
            "calcifer/０.１４４.４",
        ] {
            assert_eq!(
                parse_codex_version(user_agent),
                None,
                "{user_agent} must not spoof a supported release"
            );
        }
    }

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic broken pipe",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn eof_and_broken_pipe_are_unverified_before_and_after_the_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, events) = mpsc::sync_channel(1);
        sender
            .send(StdoutEvent::Eof)
            .map_err(|_| io::Error::other("synthetic EOF must reach the receiver"))?;
        let eof = receive_result_from(
            &events,
            RATE_LIMITS_REQUEST_ID,
            Instant::now() + Duration::from_secs(1),
        )
        .err()
        .ok_or_else(|| io::Error::other("EOF must interrupt the observation"))?;

        let mut writer = BrokenPipeWriter;
        let broken_pipe = write_json_line(&mut writer, &json!({ "id": 1 }))
            .err()
            .ok_or_else(|| io::Error::other("broken pipe must interrupt the observation"))?;

        for transport in [eof, broken_pipe] {
            assert_eq!(transport, CodexUsageError::Transport);

            let before_gate = CodexUsageFailure::before_gate(transport);
            assert_eq!(
                before_gate.compatibility(),
                CodexCompatibilityStatus::Unverified
            );
            assert!(before_gate.codex_version().is_none());

            let after_gate = CodexUsageFailure::after_gate(transport, "0.144.4");
            assert_eq!(
                after_gate.compatibility(),
                CodexCompatibilityStatus::Unverified
            );
            assert_eq!(after_gate.codex_version(), Some("0.144.4"));
        }
        Ok(())
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
        let missing_required_rate_limits = parse_rate_limits_result(json!({
            "rateLimitsByLimitId": {
                "codex": {
                    "primary": { "usedPercent": 73 }
                }
            }
        }));
        let null_required_rate_limits = parse_rate_limits_result(json!({
            "rateLimits": null,
            "rateLimitsByLimitId": {
                "codex": {
                    "primary": { "usedPercent": 73 }
                }
            }
        }));

        assert_eq!(malformed, Err(CodexUsageError::Protocol));
        assert_eq!(empty, Err(CodexUsageError::Protocol));
        assert_eq!(missing_required_rate_limits, Err(CodexUsageError::Protocol));
        assert_eq!(null_required_rate_limits, Err(CodexUsageError::Protocol));
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
        let provider = decode_response(
            r#"{"id":1,"error":{"code":-32000,"message":"raw backend detail"}}"#,
            1,
        );
        let malformed_error = decode_response(r#"{"id":1,"error":null}"#, 1);

        assert_eq!(unsupported, Err(CodexUsageError::Unsupported));
        assert_eq!(authentication, Err(CodexUsageError::Authentication));
        assert_eq!(provider, Err(CodexUsageError::Provider));
        assert_eq!(malformed_error, Err(CodexUsageError::Protocol));
        for error in [
            CodexUsageError::Unsupported,
            CodexUsageError::Authentication,
            CodexUsageError::Protocol,
            CodexUsageError::Provider,
        ] {
            assert!(!error.to_string().contains("raw"));
        }
    }

    #[test]
    fn rejects_ambiguous_json_rpc_response_envelopes() {
        for malformed in [
            r#"{"id":1,"result":{},"error":{"code":-32600,"message":"raw authentication required"}}"#,
            r#"{"id":1}"#,
        ] {
            assert_eq!(
                decode_response(malformed, 1),
                Err(CodexUsageError::Protocol),
                "a response must contain exactly one of result or error"
            );

            let failure = CodexUsageFailure::after_gate(CodexUsageError::Protocol, "0.144.4");
            assert_eq!(
                failure.compatibility(),
                CodexCompatibilityStatus::Incompatible
            );
            assert!(!failure.to_string().contains("raw"));
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
    fn rejects_unvalidated_executable_names_before_spawning()
    -> Result<(), Box<dyn std::error::Error>> {
        let result = read_account_usage(
            Path::new("codex"),
            Path::new("profile-home"),
            Path::new("neutral-working-directory"),
            Duration::from_secs(1),
        );

        let failure = result
            .err()
            .ok_or_else(|| io::Error::other("relative executable must fail"))?;
        assert_eq!(failure.kind(), CodexUsageError::Spawn);
        assert_eq!(
            failure.compatibility(),
            CodexCompatibilityStatus::Unverified
        );
        assert!(failure.codex_version().is_none());
        Ok(())
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

    #[cfg(unix)]
    #[test]
    fn thread_projection_and_lifecycle_ignore_provider_content()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sandbox = std::env::temp_dir().join(format!(
            "calcifer-thread-projection-{}-{nonce}",
            std::process::id()
        ));
        let home = sandbox.join("home");
        let sessions = home.join("sessions");
        let workspace = sandbox.join("workspace");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&sessions)?;
        std::fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let thread_id = uuid::Uuid::new_v4().to_string();
        let rollout = sessions.join(format!("rollout-synthetic-{thread_id}.jsonl"));
        let mut options = std::fs::OpenOptions::new();
        let mut file = options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&rollout)?;
        for line in [
            json!({
                "timestamp": "2026-07-15T00:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": thread_id,
                    "cwd": workspace,
                    "cli_version": "0.144.4",
                    "source": "cli",
                    "parent_thread_id": null,
                    "base_instructions": "prompt sentinel must be ignored"
                }
            }),
            json!({
                "timestamp": "2026-07-15T00:00:01Z",
                "type": "response_item",
                "payload": { "message": "response sentinel must be ignored" }
            }),
            json!({
                "timestamp": "2026-07-15T00:00:02Z",
                "type": "event_msg",
                "payload": { "type": "task_started" }
            }),
            json!({
                "timestamp": "2026-07-15T00:00:03Z",
                "type": "response_item",
                "payload": { "tool_args": "tool arguments sentinel must be ignored" }
            }),
            json!({
                "timestamp": "2026-07-15T00:00:04Z",
                "type": "event_msg",
                "payload": { "type": "turn_aborted" }
            }),
        ] {
            serde_json::to_writer(&mut file, &line)?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;

        let wire: WireThread = serde_json::from_value(json!({
            "id": thread_id,
            "parentThreadId": null,
            "ephemeral": false,
            "updatedAt": 1_800_000_000,
            "recencyAt": 1_800_000_001,
            "cwd": workspace,
            "cliVersion": "0.144.4",
            "source": "cli",
            "path": rollout,
            "preview": "preview sentinel must be ignored",
            "turns": [{ "tool": "tool arguments sentinel must be ignored" }]
        }))?;
        let canonical_workspace = std::fs::canonicalize(&workspace)?;
        let metadata =
            validate_thread_projection(wire, &canonical_workspace, &home, "0.144.4", Some(false))?;
        let lifecycle = inspect_rollout_lifecycle(&metadata, &canonical_workspace)?;

        assert_eq!(metadata.thread_id, thread_id);
        assert_eq!(lifecycle, CodexThreadLifecycle::Interrupted);
        let projection_debug = format!("{metadata:?} {lifecycle:?}");
        for sentinel in [
            "prompt sentinel",
            "response sentinel",
            "tool arguments sentinel",
            "preview sentinel",
        ] {
            assert!(!projection_debug.contains(sentinel));
        }

        let other_workspace = sandbox.join("other-workspace");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&other_workspace)?;
        let wrong_cwd: WireThread = serde_json::from_value(json!({
            "id": thread_id,
            "parentThreadId": null,
            "ephemeral": false,
            "updatedAt": 1_800_000_000,
            "recencyAt": null,
            "cwd": other_workspace,
            "cliVersion": "0.144.4",
            "source": "cli",
            "path": rollout
        }))?;
        let cwd_error = validate_thread_projection(
            wrong_cwd,
            &canonical_workspace,
            &home,
            "0.144.4",
            Some(false),
        )
        .err()
        .ok_or_else(|| io::Error::other("thread from another cwd was accepted"))?;
        assert_eq!(cwd_error, CodexThreadError::CwdMismatch);

        let archived_sessions = home.join("archived_sessions");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&archived_sessions)?;
        let archived_rollout = archived_sessions.join(format!("rollout-{thread_id}.jsonl"));
        let mut archived_options = std::fs::OpenOptions::new();
        archived_options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&archived_rollout)?
            .write_all(b"{}\n")?;
        let archived_wire = || {
            serde_json::from_value::<WireThread>(json!({
                "id": thread_id,
                "parentThreadId": null,
                "ephemeral": false,
                "updatedAt": 1_800_000_000,
                "recencyAt": null,
                "cwd": workspace,
                "cliVersion": "0.144.4",
                "source": "cli",
                "path": archived_rollout
            }))
        };
        let archive_error = validate_thread_projection(
            archived_wire()?,
            &canonical_workspace,
            &home,
            "0.144.4",
            Some(false),
        )
        .err()
        .ok_or_else(|| io::Error::other("archived rollout was accepted as active"))?;
        assert_eq!(
            archive_error,
            CodexThreadError::Protocol,
            "an archived rollout returned in the active list must fail closed"
        );
        assert!(
            validate_thread_projection(
                archived_wire()?,
                &canonical_workspace,
                &home,
                "0.144.4",
                Some(true)
            )?
            .archived
        );

        std::fs::remove_dir_all(sandbox)?;
        Ok(())
    }

    #[test]
    fn thread_rpc_failures_are_typed_and_redacted() {
        for (message, expected) in [
            (
                "session secret@example.invalid is archived",
                CodexThreadError::Archived,
            ),
            (
                "no rollout found for secret@example.invalid",
                CodexThreadError::Missing,
            ),
            (
                "authentication required secret@example.invalid",
                CodexThreadError::Authentication,
            ),
            ("backend secret@example.invalid", CodexThreadError::Provider),
        ] {
            let response = format!(r#"{{"id":1,"error":{{"code":-32000,"message":"{message}"}}}}"#);
            let error = decode_thread_response(&response, 1)
                .err()
                .unwrap_or(CodexThreadError::Protocol);
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("secret@example.invalid"));
        }
    }
}
