//! Read-only Codex account usage through the official app-server protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod handoff_compat;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod json;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod monitor;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod remote;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod supervisor;

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) use supervisor::run_internal_fixture;

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) use supervisor::{internal_production_role_requested, run_internal_production_role};
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) use supervisor::{internal_tui_launcher_requested, run_internal_tui_launcher};

/// Capability proving that the installed Codex process passed the exact
/// identity-adapter initialize/home/version gate.
///
/// The production constructor is private to this provider module. Other
/// modules can receive and consume the capability but cannot mint one.
#[derive(Clone, Copy)]
pub(crate) struct CodexIdentityAdapter {
    _private: (),
}

impl CodexIdentityAdapter {
    const fn v0_144_4() -> Self {
        Self { _private: () }
    }

    pub(crate) const fn id(self) -> &'static str {
        Self::supported_id()
    }

    pub(crate) const fn version(self) -> &'static str {
        Self::supported_version()
    }

    pub(crate) const fn supported_id() -> &'static str {
        "codex-auth-json/0.144.4/v1"
    }

    pub(crate) const fn supported_version() -> &'static str {
        "0.144.4"
    }

    #[cfg(all(test, unix))]
    pub(crate) const fn for_test() -> Self {
        Self::v0_144_4()
    }
}

pub(crate) const CLI_FILE_CREDENTIALS_OVERRIDE: &str = r#"cli_auth_credentials_store="file""#;
pub(crate) const MCP_OAUTH_FILE_CREDENTIALS_OVERRIDE: &str =
    r#"mcp_oauth_credentials_store="file""#;

const MANAGED_ENVIRONMENT_DENYLIST: &[&str] = &[
    // Calcifer's private supervisor bootstrap is authority-bearing. Provider
    // descendants must never inherit enough of it to dispatch another role or
    // retain the anchor completion endpoint.
    "CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE",
    "CALCIFER_INTERNAL_CODEX_PROFILE_ID",
    "CALCIFER_INTERNAL_CODEX_THREAD_ID",
    "CALCIFER_INTERNAL_CODEX_EXECUTABLE",
    "CALCIFER_INTERNAL_CODEX_FOREGROUND_PROCESS_GROUP",
    "CALCIFER_SUPERVISOR_READINESS_FD",
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
const MAX_VERSION_OUTPUT_BYTES: usize = 256;
// Pinned upstream 0.144.4 rollout filesystem scans stop at this many files,
// while the v2 response omits the internal `reached_scan_cap` bit.
const UPSTREAM_ROLLOUT_SCAN_FILE_CAP: usize = 10_000;
const ROLLOUT_SNAPSHOT_NODE_CAP: usize = 20_000;
const THREAD_PAGE_SIZE: u32 = 100;
const MAX_THREAD_PAGES_PER_STATE: usize = 8;
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(target_os = "macos")]
const MACOS_GROUP_KILL_RETRY_TIMEOUT: Duration = Duration::from_secs(2);
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
    pub(crate) rollout_fingerprint: CodexRolloutFingerprint,
    rollout_path: PathBuf,
    rollout_relative_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CodexRolloutFingerprint {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) length: u64,
    pub(crate) modified_seconds: i64,
    pub(crate) modified_nanoseconds: i64,
    pub(crate) changed_seconds: i64,
    pub(crate) changed_nanoseconds: i64,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RolloutNodeKind {
    RegularFile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RolloutFileFingerprint {
    relative_path: PathBuf,
    kind: RolloutNodeKind,
    change: CodexRolloutFingerprint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RolloutRootSnapshot {
    files: Vec<RolloutFileFingerprint>,
    complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RolloutStoreSnapshot {
    active: RolloutRootSnapshot,
    archived: RolloutRootSnapshot,
}

impl RolloutStoreSnapshot {
    const fn complete(&self) -> bool {
        self.active.complete && self.archived.complete
    }

    fn matches_thread(&self, thread: &CodexThreadMetadata) -> bool {
        let root = if thread.archived {
            &self.archived
        } else {
            &self.active
        };
        root.files
            .binary_search_by(|file| file.relative_path.cmp(&thread.rollout_relative_path))
            .ok()
            .is_some_and(|index| {
                root.files[index].kind == RolloutNodeKind::RegularFile
                    && root.files[index].change == thread.rollout_fingerprint
            })
    }
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
    command.env_clear();
    for (name, value) in std::env::vars_os() {
        if !is_managed_environment_override(&name) {
            command.env(name, value);
        }
    }
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
        || normalized.starts_with("CALCIFER_")
        || normalized.starts_with("OPENAI_")
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
    inherited_provider_lease: Option<&File>,
) -> Result<CodexUsageObservation, CodexUsageFailure> {
    let (mut process, codex_version, deadline) = initialize_compatible_app_server(
        codex_executable,
        codex_home,
        working_directory,
        timeout,
        inherited_provider_lease,
    )?;

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

/// Verifies the installed App Server before enabling the persisted 0.144.4
/// auth projection used for private provider identity binding.
///
/// This performs only the initialize/home/version gate. It does not call an
/// account endpoint, refresh endpoint, or browser login flow.
pub(crate) fn verify_codex_identity_adapter(
    codex_executable: &Path,
    codex_home: &Path,
    working_directory: &Path,
    timeout: Duration,
    inherited_provider_lease: Option<&File>,
) -> Result<CodexIdentityAdapter, CodexUsageFailure> {
    let (_process, codex_version, _deadline) = initialize_compatible_app_server(
        codex_executable,
        codex_home,
        working_directory,
        timeout,
        inherited_provider_lease,
    )?;
    if codex_version == "0.144.4" {
        Ok(CodexIdentityAdapter::v0_144_4())
    } else {
        Err(CodexUsageFailure::incompatible(
            CodexUsageError::Unsupported,
            Some(codex_version),
        ))
    }
}

fn initialize_compatible_app_server(
    codex_executable: &Path,
    codex_home: &Path,
    working_directory: &Path,
    timeout: Duration,
    inherited_provider_lease: Option<&File>,
) -> Result<(AppServerProcess, String, Instant), CodexUsageFailure> {
    if !codex_executable.is_absolute() {
        return Err(CodexUsageFailure::before_gate(CodexUsageError::Spawn));
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CodexUsageFailure::before_gate(CodexUsageError::Timeout))?;
    let mut process = AppServerProcess::spawn(
        codex_executable,
        codex_home,
        working_directory,
        inherited_provider_lease,
    )
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
    Ok((process, codex_version, deadline))
}

/// Reads only the official CLI version without relying on App Server support.
///
/// Explicit exact resume uses this bounded probe to distinguish a known
/// adapter version from a clearly newer CLI whose official exact-resume
/// command remains usable even if its App Server protocol changed.
pub(crate) fn probe_codex_version(
    codex_executable: &Path,
    codex_home: &Path,
    working_directory: &Path,
    timeout: Duration,
    inherited_provider_lease: Option<&File>,
) -> Result<String, CodexThreadError> {
    let deadline = thread_deadline(codex_executable, timeout)?;
    let command = managed_command(codex_executable, codex_home);
    probe_codex_version_command(
        command,
        working_directory,
        deadline,
        inherited_provider_lease,
    )
}

/// A closed, payload-free timeout boundary inside the bounded `codex
/// --version` probe. The compatibility gate maps these values into its own
/// pre-version timeout catalog without exposing process identity or output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexVersionProbeTimeoutOrigin {
    ChildExit,
    StdoutDrain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CodexVersionProbeFailure {
    error: CodexThreadError,
    timeout_origin: Option<CodexVersionProbeTimeoutOrigin>,
    cleanup_error: Option<CodexThreadError>,
}

impl CodexVersionProbeFailure {
    const fn timeout(origin: CodexVersionProbeTimeoutOrigin) -> Self {
        Self {
            error: CodexThreadError::Timeout,
            timeout_origin: Some(origin),
            cleanup_error: None,
        }
    }

    const fn timeout_with_cleanup(
        origin: CodexVersionProbeTimeoutOrigin,
        cleanup_error: Option<CodexThreadError>,
    ) -> Self {
        Self {
            error: CodexThreadError::Timeout,
            timeout_origin: Some(origin),
            cleanup_error,
        }
    }

    pub(crate) const fn error(self) -> CodexThreadError {
        self.error
    }

    pub(crate) const fn timeout_origin(self) -> Option<CodexVersionProbeTimeoutOrigin> {
        self.timeout_origin
    }

    pub(crate) const fn cleanup_error(self) -> Option<CodexThreadError> {
        self.cleanup_error
    }

    const fn release(self) -> CodexThreadError {
        self.error
    }
}

impl From<CodexThreadError> for CodexVersionProbeFailure {
    fn from(error: CodexThreadError) -> Self {
        Self {
            error,
            timeout_origin: None,
            cleanup_error: None,
        }
    }
}

fn probe_codex_version_command(
    command: Command,
    working_directory: &Path,
    deadline: Instant,
    inherited_provider_lease: Option<&File>,
) -> Result<String, CodexThreadError> {
    probe_codex_version_command_with_origin(
        command,
        working_directory,
        deadline,
        inherited_provider_lease,
    )
    .map_err(CodexVersionProbeFailure::release)
}

pub(crate) fn probe_codex_version_command_with_origin(
    mut command: Command,
    working_directory: &Path,
    deadline: Instant,
    inherited_provider_lease: Option<&File>,
) -> Result<String, CodexVersionProbeFailure> {
    configure_own_process_group(&mut command);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .current_dir(working_directory);
    if Instant::now() >= deadline {
        return Err(CodexVersionProbeFailure::timeout(
            CodexVersionProbeTimeoutOrigin::ChildExit,
        ));
    }
    let mut child = spawn_with_optional_inherited_fd(command, inherited_provider_lease)
        .map_err(|_| CodexVersionProbeFailure::from(CodexThreadError::Spawn))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            force_terminate_process_tree(&mut child)
                .map_err(|_| CodexVersionProbeFailure::from(CodexThreadError::Transport))?;
            return Err(CodexThreadError::Spawn.into());
        }
    };
    let (output_sender, output_receiver) = mpsc::sync_channel(1);
    let reader = match thread::Builder::new()
        .name("calcifer-codex-version".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take((MAX_VERSION_OUTPUT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = output_sender.send(result);
        }) {
        Ok(reader) => reader,
        Err(_) => {
            force_terminate_process_tree(&mut child)
                .map_err(|_| CodexVersionProbeFailure::from(CodexThreadError::Transport))?;
            return Err(CodexThreadError::Spawn.into());
        }
    };

    loop {
        match child_exit_observed_without_reaping(&mut child) {
            Ok(true) => {
                let status = reap_exited_process_tree(&mut child)
                    .map_err(|_| CodexVersionProbeFailure::from(CodexThreadError::Transport))?;
                let remaining = match deadline.checked_duration_since(Instant::now()) {
                    Some(remaining) => remaining,
                    None => {
                        // The pipe can remain open in an escaped descendant.
                        // Dropping the handle detaches that reader instead of
                        // violating the probe's authoritative deadline.
                        drop(reader);
                        return Err(CodexVersionProbeFailure::timeout(
                            CodexVersionProbeTimeoutOrigin::StdoutDrain,
                        ));
                    }
                };
                let bytes = match output_receiver.recv_timeout(remaining) {
                    Ok(Ok(bytes)) => bytes,
                    Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
                        join_version_reader_until(reader, deadline)?;
                        return Err(CodexThreadError::Transport.into());
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        drop(reader);
                        return Err(CodexVersionProbeFailure::timeout(
                            CodexVersionProbeTimeoutOrigin::StdoutDrain,
                        ));
                    }
                };
                join_version_reader_until(reader, deadline)?;
                if !status.success() {
                    return Err(CodexThreadError::Provider.into());
                }
                return parse_codex_version_output(&bytes).map_err(Into::into);
            }
            Ok(false) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(false) => {
                // Preserve the first timeout boundary even when best-effort
                // process-tree or pipe cleanup also fails. No compatibility
                // capability is returned from this path.
                let cleanup_error = force_terminate_process_tree(&mut child)
                    .err()
                    .map(|_| CodexThreadError::Transport);
                drop(reader);
                return Err(CodexVersionProbeFailure::timeout_with_cleanup(
                    CodexVersionProbeTimeoutOrigin::ChildExit,
                    cleanup_error,
                ));
            }
            Err(_) => {
                force_terminate_process_tree(&mut child)
                    .map_err(|_| CodexVersionProbeFailure::from(CodexThreadError::Transport))?;
                join_version_reader_until(reader, deadline)?;
                return Err(CodexThreadError::Transport.into());
            }
        }
    }
}

fn join_version_reader_until(
    reader: JoinHandle<()>,
    deadline: Instant,
) -> Result<(), CodexVersionProbeFailure> {
    join_app_server_io_handle_until(reader, deadline).map_err(|error| {
        if error.kind() == io::ErrorKind::TimedOut {
            CodexVersionProbeFailure::timeout(CodexVersionProbeTimeoutOrigin::StdoutDrain)
        } else {
            CodexThreadError::Transport.into()
        }
    })
}

fn parse_codex_version_output(bytes: &[u8]) -> Result<String, CodexThreadError> {
    if bytes.len() > MAX_VERSION_OUTPUT_BYTES {
        return Err(CodexThreadError::Protocol);
    }
    let output = std::str::from_utf8(bytes).map_err(|_| CodexThreadError::Protocol)?;
    let mut tokens = output.split_ascii_whitespace();
    if tokens.next() != Some("codex-cli") {
        return Err(CodexThreadError::Protocol);
    }
    let version = tokens.next().ok_or(CodexThreadError::Protocol)?;
    if tokens.next().is_some() {
        return Err(CodexThreadError::Protocol);
    }
    normalize_codex_version(version).ok_or(CodexThreadError::Protocol)
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
    inherited_provider_lease: Option<&File>,
) -> Result<CodexThreadInventory, CodexThreadError> {
    let canonical_cwd = fs::canonicalize(canonical_cwd).map_err(|_| CodexThreadError::Protocol)?;
    if !canonical_cwd.is_dir() {
        return Err(CodexThreadError::Protocol);
    }
    let canonical_cwd_string = canonical_cwd
        .to_str()
        .ok_or(CodexThreadError::Protocol)?
        .to_owned();
    let rollout_before = snapshot_rollout_store(codex_home)?;
    let deadline = thread_deadline(codex_executable, timeout)?;
    let (mut process, codex_version) = initialize_thread_client(
        codex_executable,
        codex_home,
        neutral_working_directory,
        deadline,
        inherited_provider_lease,
    )?;

    if !rollout_before.complete() {
        return Ok(CodexThreadInventory {
            codex_version,
            threads: Vec::new(),
            complete: false,
        });
    }

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
    let rollout_after = snapshot_rollout_store(codex_home)?;
    complete &= rollout_after.complete()
        && rollout_before == rollout_after
        && threads
            .iter()
            .all(|thread| rollout_after.matches_thread(thread));
    threads.sort_by(|left, right| left.thread_id.cmp(&right.thread_id));
    Ok(CodexThreadInventory {
        codex_version,
        threads,
        complete,
    })
}

fn snapshot_rollout_store(codex_home: &Path) -> Result<RolloutStoreSnapshot, CodexThreadError> {
    snapshot_rollout_store_with_limits(
        codex_home,
        UPSTREAM_ROLLOUT_SCAN_FILE_CAP,
        ROLLOUT_SNAPSHOT_NODE_CAP,
    )
}

fn snapshot_rollout_store_with_limits(
    codex_home: &Path,
    file_cap: usize,
    node_cap: usize,
) -> Result<RolloutStoreSnapshot, CodexThreadError> {
    if file_cap == 0 || node_cap == 0 {
        return Err(CodexThreadError::SessionSchema);
    }
    let canonical_home =
        fs::canonicalize(codex_home).map_err(|_| CodexThreadError::SessionSchema)?;
    validate_managed_home_boundary(&canonical_home)?;
    Ok(RolloutStoreSnapshot {
        active: snapshot_rollout_root(&canonical_home, "sessions", file_cap, node_cap)?,
        archived: snapshot_rollout_root(&canonical_home, "archived_sessions", file_cap, node_cap)?,
    })
}

fn snapshot_rollout_root(
    canonical_home: &Path,
    name: &str,
    file_cap: usize,
    node_cap: usize,
) -> Result<RolloutRootSnapshot, CodexThreadError> {
    let root = canonical_home.join(name);
    let root_metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RolloutRootSnapshot {
                files: Vec::new(),
                complete: true,
            });
        }
        Err(_) => return Err(CodexThreadError::SessionSchema),
    };
    validate_snapshot_directory(&root_metadata)?;
    let canonical_root = fs::canonicalize(&root).map_err(|_| CodexThreadError::SessionSchema)?;
    if canonical_root != root || !canonical_root.starts_with(canonical_home) {
        return Err(CodexThreadError::SessionSchema);
    }

    let mut directories = vec![canonical_root.clone()];
    let mut files = Vec::new();
    let mut node_count = 0_usize;
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory).map_err(|_| CodexThreadError::SessionSchema)?;
        for entry in entries {
            let entry = entry.map_err(|_| CodexThreadError::SessionSchema)?;
            node_count = node_count.saturating_add(1);
            if node_count > node_cap {
                return Ok(RolloutRootSnapshot {
                    files,
                    complete: false,
                });
            }
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| CodexThreadError::SessionSchema)?;
            if metadata.file_type().is_symlink() {
                return Err(CodexThreadError::SessionSchema);
            }
            if metadata.file_type().is_dir() {
                validate_snapshot_directory(&metadata)?;
                directories.push(path);
                continue;
            }
            if !metadata.file_type().is_file() {
                return Err(CodexThreadError::SessionSchema);
            }
            validate_snapshot_file(&metadata)?;
            if !rollout_count_is_below_cap(files.len().saturating_add(1), file_cap) {
                return Ok(RolloutRootSnapshot {
                    files,
                    complete: false,
                });
            }
            files.push(rollout_file_fingerprint(&canonical_root, &path, &metadata)?);
        }
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(RolloutRootSnapshot {
        files,
        complete: true,
    })
}

const fn rollout_count_is_below_cap(count: usize, cap: usize) -> bool {
    count < cap
}

#[cfg(unix)]
fn validate_snapshot_directory(metadata: &fs::Metadata) -> Result<(), CodexThreadError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() < 1
    {
        return Err(CodexThreadError::SessionSchema);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_managed_home_boundary(path: &Path) -> Result<(), CodexThreadError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path).map_err(|_| CodexThreadError::SessionSchema)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() < 1
    {
        return Err(CodexThreadError::SessionSchema);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_managed_home_boundary(_path: &Path) -> Result<(), CodexThreadError> {
    Err(CodexThreadError::SessionSchema)
}

#[cfg(not(unix))]
fn validate_snapshot_directory(metadata: &fs::Metadata) -> Result<(), CodexThreadError> {
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(CodexThreadError::SessionSchema)
    }
}

#[cfg(unix)]
fn validate_snapshot_file(metadata: &fs::Metadata) -> Result<(), CodexThreadError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(CodexThreadError::SessionSchema);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_snapshot_file(metadata: &fs::Metadata) -> Result<(), CodexThreadError> {
    if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(CodexThreadError::SessionSchema)
    }
}

fn rollout_file_fingerprint(
    root: &Path,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<RolloutFileFingerprint, CodexThreadError> {
    let relative_path = path
        .strip_prefix(root)
        .map_err(|_| CodexThreadError::SessionSchema)?
        .to_path_buf();
    let change = rollout_change_fingerprint(metadata)?;
    Ok(RolloutFileFingerprint {
        relative_path,
        kind: RolloutNodeKind::RegularFile,
        change,
    })
}

#[cfg(unix)]
fn rollout_change_fingerprint(
    metadata: &fs::Metadata,
) -> Result<CodexRolloutFingerprint, CodexThreadError> {
    use std::os::unix::fs::MetadataExt;

    Ok(CodexRolloutFingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn rollout_change_fingerprint(
    metadata: &fs::Metadata,
) -> Result<CodexRolloutFingerprint, CodexThreadError> {
    use std::time::UNIX_EPOCH;

    let modified = metadata
        .modified()
        .map_err(|_| CodexThreadError::SessionSchema)?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CodexThreadError::SessionSchema)?;
    let seconds = i64::try_from(modified.as_secs()).map_err(|_| CodexThreadError::SessionSchema)?;
    Ok(CodexRolloutFingerprint {
        device: 0,
        inode: 0,
        length: metadata.len(),
        modified_seconds: seconds,
        modified_nanoseconds: i64::from(modified.subsec_nanos()),
        changed_seconds: seconds,
        changed_nanoseconds: i64::from(modified.subsec_nanos()),
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
    inherited_provider_lease: Option<&File>,
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
        inherited_provider_lease,
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
    inherited_provider_lease: Option<&File>,
) -> Result<(AppServerProcess, String), CodexThreadError> {
    let mut process = AppServerProcess::spawn(
        codex_executable,
        codex_home,
        neutral_working_directory,
        inherited_provider_lease,
    )
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
    let (archived, rollout_path, rollout_relative_path, rollout_fingerprint) =
        validate_rollout_path(codex_home, &rollout_path)?;
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
        rollout_fingerprint,
        rollout_path,
        rollout_relative_path,
    })
}

fn validate_canonical_uuid(value: &str) -> Result<(), CodexThreadError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| CodexThreadError::Protocol)?;
    if parsed.to_string() != value {
        return Err(CodexThreadError::Protocol);
    }
    Ok(())
}

fn validate_rollout_path(
    codex_home: &Path,
    path: &Path,
) -> Result<(bool, PathBuf, PathBuf, CodexRolloutFingerprint), CodexThreadError> {
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
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
            || metadata.len() > MAX_ROLLOUT_BYTES as u64
        {
            return Err(CodexThreadError::SessionSchema);
        }
        let canonical_home =
            fs::canonicalize(codex_home).map_err(|_| CodexThreadError::SessionSchema)?;
        validate_managed_home_boundary(&canonical_home)?;
        let canonical_path = fs::canonicalize(path).map_err(|_| CodexThreadError::Missing)?;
        let relative_from_home = path
            .strip_prefix(codex_home)
            .map_err(|_| CodexThreadError::SessionSchema)?;
        if canonical_home.join(relative_from_home) != canonical_path {
            return Err(CodexThreadError::SessionSchema);
        }
        let active_root = canonical_home.join("sessions");
        let archived_root = canonical_home.join("archived_sessions");
        let (archived, root) = if canonical_path.starts_with(&active_root) {
            (false, active_root)
        } else if canonical_path.starts_with(&archived_root) {
            (true, archived_root)
        } else {
            return Err(CodexThreadError::SessionSchema);
        };
        validate_rollout_ancestor_chain(&canonical_home, &root, &canonical_path)?;
        let relative_path = canonical_path
            .strip_prefix(&root)
            .map_err(|_| CodexThreadError::SessionSchema)?
            .to_path_buf();
        let fingerprint = rollout_change_fingerprint(&metadata)?;
        Ok((archived, canonical_path, relative_path, fingerprint))
    }

    #[cfg(not(unix))]
    {
        let _ = (codex_home, path);
        Err(CodexThreadError::SessionSchema)
    }
}

#[cfg(unix)]
fn validate_rollout_ancestor_chain(
    canonical_home: &Path,
    root: &Path,
    rollout_path: &Path,
) -> Result<(), CodexThreadError> {
    if !root.starts_with(canonical_home) || rollout_path.parent().is_none() {
        return Err(CodexThreadError::SessionSchema);
    }
    let mut directory = rollout_path
        .parent()
        .ok_or(CodexThreadError::SessionSchema)?;
    loop {
        if !directory.starts_with(root) {
            return Err(CodexThreadError::SessionSchema);
        }
        let metadata =
            fs::symlink_metadata(directory).map_err(|_| CodexThreadError::SessionSchema)?;
        validate_snapshot_directory(&metadata)?;
        if directory == root {
            return Ok(());
        }
        directory = directory.parent().ok_or(CodexThreadError::SessionSchema)?;
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
    validate_open_rollout(&file, metadata)?;
    let mut reader = BufReader::new(CappedReader::new(file, MAX_ROLLOUT_BYTES as u64));
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

#[cfg(unix)]
fn validate_open_rollout(
    file: &fs::File,
    expected: &CodexThreadMetadata,
) -> Result<(), CodexThreadError> {
    use std::os::unix::fs::MetadataExt;

    let opened = file
        .metadata()
        .map_err(|_| CodexThreadError::SessionSchema)?;
    let path = fs::symlink_metadata(&expected.rollout_path)
        .map_err(|_| CodexThreadError::SessionSchema)?;
    let current_fingerprint = rollout_change_fingerprint(&opened)?;
    if current_fingerprint != expected.rollout_fingerprint
        || path.dev() != opened.dev()
        || path.ino() != opened.ino()
        || !opened.file_type().is_file()
        || !path.file_type().is_file()
        || path.file_type().is_symlink()
        || opened.uid() != rustix::process::getuid().as_raw()
        || opened.mode() & 0o022 != 0
        || opened.nlink() != 1
        || opened.len() > MAX_ROLLOUT_BYTES as u64
    {
        return Err(CodexThreadError::SessionSchema);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_open_rollout(
    _file: &fs::File,
    _expected: &CodexThreadMetadata,
) -> Result<(), CodexThreadError> {
    Err(CodexThreadError::SessionSchema)
}

struct CappedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> CappedReader<R> {
    const fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rollout exceeds limit",
                )),
            };
        }
        let allowed = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.remaining = self.remaining.saturating_sub(read as u64);
        Ok(read)
    }
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
    normalize_codex_version(version)
}

fn normalize_codex_version(version: &str) -> Option<String> {
    if version.is_empty() || version.len() > 64 || !version.is_ascii() {
        return None;
    }

    let without_build = match version.split_once('+') {
        Some((without_build, build)) => {
            if build.contains('+') || !valid_semver_identifiers(build, false) {
                return None;
            }
            without_build
        }
        None => version,
    };
    let core = match without_build.split_once('-') {
        Some((core, prerelease)) => {
            if !valid_semver_identifiers(prerelease, true) {
                return None;
            }
            core
        }
        None => without_build,
    };
    let mut components = core.split('.');
    let major = parse_version_component(components.next()?)?;
    let minor = parse_version_component(components.next()?)?;
    let patch = parse_version_component(components.next()?)?;
    if components.next().is_some() {
        return None;
    }
    let normalized_core = format!("{major}.{minor}.{patch}");
    if normalized_core != core {
        return None;
    }
    Some(version.to_owned())
}

fn valid_semver_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !(reject_numeric_leading_zero
                    && identifier.len() > 1
                    && identifier.starts_with('0')
                    && identifier.bytes().all(|byte| byte.is_ascii_digit()))
        })
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
    reaped: bool,
    stdin: Option<ChildStdin>,
    stdout_events: Option<Receiver<StdoutEvent>>,
    stdout_reader: Option<AppServerIoWorker>,
    stderr_drainer: Option<AppServerIoWorker>,
}

struct AppServerIoWorker {
    handle: JoinHandle<()>,
    completed: Receiver<Instant>,
}

impl AppServerIoWorker {
    fn join_until(self, deadline: Instant) -> io::Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.completed.recv_timeout(remaining) {
            Ok(completed_at) => {
                let joined = join_app_server_io_handle_until(self.handle, deadline);
                if completed_at < deadline {
                    joined
                } else {
                    joined.and(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Codex I/O worker exceeded its shutdown deadline",
                    )))
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // Dropping a JoinHandle detaches the blocked reader. The
                // caller receives no compatibility capability, and a later
                // AppServerProcess::drop must not repeat an unbounded join.
                drop(self.handle);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Codex I/O worker exceeded its shutdown deadline",
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                join_app_server_io_handle_until(self.handle, deadline).and(Err(io::Error::other(
                    "Codex I/O worker omitted its completion proof",
                )))
            }
        }
    }
}

fn join_app_server_io_handle_until(handle: JoinHandle<()>, deadline: Instant) -> io::Result<()> {
    while !handle.is_finished() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            drop(handle);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Codex I/O worker exceeded its shutdown deadline",
            ));
        }
        thread::sleep(remaining.min(Duration::from_millis(1)));
    }
    if Instant::now() >= deadline {
        drop(handle);
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Codex I/O worker exceeded its shutdown deadline",
        ));
    }
    handle
        .join()
        .map_err(|_| io::Error::other("Codex I/O worker panicked"))
}

impl AppServerProcess {
    fn spawn(
        codex_executable: &Path,
        codex_home: &Path,
        working_directory: &Path,
        inherited_provider_lease: Option<&File>,
    ) -> Result<Self, CodexUsageError> {
        let mut command = managed_command(codex_executable, codex_home);
        command.args(["app-server", "--stdio"]);
        Self::spawn_command(command, working_directory, inherited_provider_lease)
    }

    fn spawn_command(
        mut command: Command,
        working_directory: &Path,
        inherited_provider_lease: Option<&File>,
    ) -> Result<Self, CodexUsageError> {
        configure_own_process_group(&mut command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(working_directory);
        let mut child = spawn_with_optional_inherited_fd(command, inherited_provider_lease)
            .map_err(|_| CodexUsageError::Spawn)?;

        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                force_terminate_process_tree(&mut child).map_err(|_| CodexUsageError::Transport)?;
                return Err(CodexUsageError::Spawn);
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                force_terminate_process_tree(&mut child).map_err(|_| CodexUsageError::Transport)?;
                return Err(CodexUsageError::Spawn);
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                force_terminate_process_tree(&mut child).map_err(|_| CodexUsageError::Transport)?;
                return Err(CodexUsageError::Spawn);
            }
        };

        let (stdout_sender, stdout_events) = mpsc::sync_channel(16);
        let (stdout_completed_sender, stdout_completed) = mpsc::sync_channel(1);
        let stdout_reader_handle = match thread::Builder::new()
            .name("calcifer-codex-stdout".to_owned())
            .spawn(move || {
                read_stdout(stdout, &stdout_sender);
                let _ = stdout_completed_sender.send(Instant::now());
            }) {
            Ok(reader) => reader,
            Err(_) => {
                force_terminate_process_tree(&mut child).map_err(|_| CodexUsageError::Transport)?;
                return Err(CodexUsageError::Spawn);
            }
        };
        let stdout_reader = AppServerIoWorker {
            handle: stdout_reader_handle,
            completed: stdout_completed,
        };
        let (stderr_completed_sender, stderr_completed) = mpsc::sync_channel(1);
        let stderr_drainer_handle = match thread::Builder::new()
            .name("calcifer-codex-stderr".to_owned())
            .spawn(move || {
                drain_stderr(stderr);
                let _ = stderr_completed_sender.send(Instant::now());
            }) {
            Ok(drainer) => drainer,
            Err(_) => {
                force_terminate_process_tree(&mut child).map_err(|_| CodexUsageError::Transport)?;
                return Err(CodexUsageError::Spawn);
            }
        };
        let stderr_drainer = AppServerIoWorker {
            handle: stderr_drainer_handle,
            completed: stderr_completed,
        };

        Ok(Self {
            child,
            reaped: false,
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

    fn shutdown(&mut self) -> io::Result<()> {
        let deadline = Instant::now()
            .checked_add(GRACEFUL_SHUTDOWN_TIMEOUT)
            .ok_or_else(|| io::Error::other("Codex shutdown deadline overflowed"))?;
        self.shutdown_after_completed_request_until(deadline)
    }

    /// Closes a completed one-shot request and requires a clean exit before
    /// the caller's existing absolute deadline.
    ///
    /// A direct exit code zero observed before the deadline is the protocol
    /// success condition; reaping also sweeps that child's exact process group.
    /// Forced direct-child cleanup after the deadline never becomes success,
    /// and the group sweep does not claim that a new-session descendant is
    /// absent. This keeps compatibility probes bounded without manufacturing
    /// a stronger descendant-containment proof than the process group provides.
    fn shutdown_after_completed_request_until(&mut self, deadline: Instant) -> io::Result<()> {
        self.stdin.take();
        let child_result = if self.reaped {
            Ok(())
        } else {
            let termination = graceful_terminate_until(&mut self.child, deadline);
            self.reaped = child_reap_confirmed(&mut self.child);
            match termination {
                Ok(_) if !self.reaped => Err(io::Error::other("Codex child was not reaped")),
                Ok(status) if !status.success() => {
                    Err(io::Error::other("Codex app-server did not exit cleanly"))
                }
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            }
        };
        let worker_result = self.join_io_workers_until(deadline);
        child_result.and(worker_result)
    }

    fn join_io_workers_until(&mut self, deadline: Instant) -> io::Result<()> {
        self.stdout_events.take();
        let stdout_result = self
            .stdout_reader
            .take()
            .map_or(Ok(()), |reader| reader.join_until(deadline));
        let stderr_result = self
            .stderr_drainer
            .take()
            .map_or(Ok(()), |drainer| drainer.join_until(deadline));
        stdout_result.and(stderr_result)
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
        let _ = self.shutdown();
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

fn wait_for_child(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    loop {
        match child.wait() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn configure_own_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
    }
    #[cfg(not(unix))]
    let _ = command;
}

fn spawn_with_optional_inherited_fd(
    mut command: Command,
    inherited_provider_lease: Option<&File>,
) -> io::Result<Child> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;

        if let Some(provider_lease) = inherited_provider_lease {
            return calcifer_unix_child_fd::spawn_with_inherited_fd(
                command,
                provider_lease.as_fd(),
            );
        }
    }
    #[cfg(not(unix))]
    if inherited_provider_lease.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "provider lease inheritance is unsupported on this platform",
        ));
    }
    command.spawn()
}

pub(super) fn force_terminate_process_tree(
    child: &mut Child,
) -> io::Result<std::process::ExitStatus> {
    #[cfg(unix)]
    let process_group = rustix::process::Pid::from_child(&*child);
    #[cfg(target_os = "macos")]
    let mut group_result = kill_process_group_for_cleanup(child, process_group);
    #[cfg(all(unix, not(target_os = "macos")))]
    let group_result = kill_process_group_for_cleanup(child, process_group);
    #[cfg(not(unix))]
    let group_result: io::Result<()> = Ok(());

    let kill_result = child.kill();
    #[cfg(target_os = "macos")]
    if group_result
        .as_ref()
        .err()
        .and_then(|error| error.raw_os_error())
        == Some(rustix::io::Errno::PERM.raw_os_error())
        && direct_kill_may_have_reached_child(&kill_result)
    {
        // The TUI can naturally exit between the initial liveness observation
        // and killpg. Keep its exact leader unreaped so PID/PGID reuse remains
        // impossible, wait briefly for a terminal WNOWAIT state after the
        // direct SIGKILL, then repeat the group sweep against that anchor.
        let deadline = Instant::now()
            .checked_add(MACOS_GROUP_KILL_RETRY_TIMEOUT)
            .unwrap_or_else(Instant::now);
        loop {
            match child_exit_observed_without_reaping(child) {
                Ok(true) => {
                    group_result = kill_process_group_for_cleanup(child, process_group);
                    break;
                }
                Ok(false) if Instant::now() < deadline => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Ok(false) | Err(_) => break,
            }
        }
    }
    let wait_result = wait_for_child(child);
    group_result?;
    if let Err(error) = kill_result {
        let already_gone = matches!(
            error.kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
        );
        #[cfg(unix)]
        let already_gone =
            already_gone || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error());
        if !already_gone {
            return Err(error);
        }
    }
    wait_result
}

#[cfg(unix)]
fn kill_process_group_for_cleanup(
    _child: &mut Child,
    process_group: rustix::process::Pid,
) -> io::Result<()> {
    match rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        #[cfg(target_os = "macos")]
        Err(rustix::io::Errno::PERM)
            if macos_anchored_zombie_group_absent(_child, process_group) =>
        {
            // Darwin can report EPERM for a group containing only its
            // waitable zombie leader. The unreaped child pins the numeric
            // identity while two stable snapshots prove no descendant
            // remains.
            Ok(())
        }
        Err(error) => Err(io::Error::from(error)),
    }
}

#[cfg(target_os = "macos")]
fn direct_kill_may_have_reached_child(result: &io::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
            ) || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
        }
    }
}

#[cfg(unix)]
pub(super) fn child_exit_observed_without_reaping(child: &mut Child) -> io::Result<bool> {
    let pid = rustix::process::Pid::from_child(child);
    retry_rustix_intr(|| {
        rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
    })
    .map(|status| {
        // Darwin can surface a pending stopped/continued notification even
        // when this non-consuming query asks for EXITED only. Those states
        // still carry live process authority and must never be reaped as an
        // exit.
        status.is_some_and(|status| status.exited() || status.killed() || status.dumped())
    })
    .map_err(io::Error::from)
}

#[cfg(unix)]
fn retry_rustix_intr<T>(
    mut operation: impl FnMut() -> Result<T, rustix::io::Errno>,
) -> Result<T, rustix::io::Errno> {
    loop {
        match operation() {
            Err(rustix::io::Errno::INTR) => {}
            result => return result,
        }
    }
}

#[cfg(not(unix))]
pub(super) fn child_exit_observed_without_reaping(child: &mut Child) -> io::Result<bool> {
    child.try_wait().map(|status| status.is_some())
}

pub(super) fn child_reap_confirmed(child: &mut Child) -> bool {
    match child.try_wait() {
        Ok(Some(_)) => true,
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error()) => true,
        Ok(None) | Err(_) => false,
    }
}

pub(super) fn reap_exited_process_tree(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    #[cfg(unix)]
    let group_result = {
        let process_group = rustix::process::Pid::from_child(&*child);
        let result =
            rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
        #[cfg(target_os = "macos")]
        let anchored_zombie_only = macos_anchored_zombie_group_absent(child, process_group);
        #[cfg(not(target_os = "macos"))]
        let anchored_zombie_only = false;
        exited_group_kill_result(result, anchored_zombie_only)
    };
    #[cfg(not(unix))]
    let group_result: io::Result<()> = Ok(());

    let wait_result = wait_for_child(child);
    group_result?;
    wait_result
}

#[cfg(unix)]
fn exited_group_kill_result(
    result: Result<(), rustix::io::Errno>,
    anchored_zombie_only: bool,
) -> Result<(), io::Error> {
    #[cfg(not(target_os = "macos"))]
    let _ = anchored_zombie_only;
    match result {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        #[cfg(target_os = "macos")]
        Err(rustix::io::Errno::PERM) if anchored_zombie_only => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

/// Proves that a Darwin process group contains only its exact, unreaped,
/// terminal leader.
///
/// EPERM alone is never absence evidence. The wait-visible child pins PID/PGID
/// reuse, and two complete process snapshots must agree that the leader is the
/// group's only zombie member.
#[cfg(target_os = "macos")]
fn macos_anchored_zombie_group_absent(
    child: &mut Child,
    process_group: rustix::process::Pid,
) -> bool {
    let direct_child = rustix::process::Pid::from_child(&*child);
    if direct_child != process_group {
        return false;
    }
    let terminal = retry_rustix_intr(|| {
        rustix::process::waitid(
            rustix::process::WaitId::Pid(direct_child),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
    })
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

fn graceful_terminate_until(
    child: &mut Child,
    deadline: Instant,
) -> io::Result<std::process::ExitStatus> {
    loop {
        match child_exit_observed_without_reaping(child) {
            Ok(true) => {
                let observed_before_deadline = Instant::now() < deadline;
                let status = reap_exited_process_tree(child)?;
                return if observed_before_deadline {
                    Ok(status)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Codex child exited after its shutdown deadline",
                    ))
                };
            }
            Ok(false) if Instant::now() < deadline => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            Ok(false) => {
                force_terminate_process_tree(child)?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Codex child exceeded its shutdown deadline",
                ));
            }
            Err(observation_error) => {
                force_terminate_process_tree(child)?;
                return Err(observation_error);
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
    fn version_probe_output_is_bounded_and_canonical() {
        assert_eq!(
            parse_codex_version_output(b"codex-cli 0.144.4\n"),
            Ok("0.144.4".to_owned())
        );
        assert_eq!(
            parse_codex_version_output(b"codex-cli 0.145.0-alpha.11\n"),
            Ok("0.145.0-alpha.11".to_owned())
        );
        for invalid in [
            b"codex 0.144.4\n".as_slice(),
            b"codex-cli latest\n".as_slice(),
            b"codex-cli 0.144.4 extra\n".as_slice(),
            b"codex-cli 0.145.0-alpha.01\n".as_slice(),
            b"codex-cli \xff\n".as_slice(),
        ] {
            assert_eq!(
                parse_codex_version_output(invalid),
                Err(CodexThreadError::Protocol)
            );
        }
        assert_eq!(
            parse_codex_version_output(&vec![b'x'; MAX_VERSION_OUTPUT_BYTES + 1]),
            Err(CodexThreadError::Protocol)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn exit_observation_keeps_group_leader_waitable_until_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("sh");
        configure_own_process_group(&mut command);
        let mut child = command
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let process_group = rustix::process::Pid::from_child(&child);
        let deadline = Instant::now() + Duration::from_secs(2);

        while !child_exit_observed_without_reaping(&mut child)? {
            if Instant::now() >= deadline {
                let _ = force_terminate_process_tree(&mut child);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "synthetic child did not exit",
                )
                .into());
            }
            thread::sleep(Duration::from_millis(10));
        }

        let still_waitable = rustix::process::waitid(
            rustix::process::WaitId::Pid(process_group),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )?;
        assert!(still_waitable.is_some());

        let status = reap_exited_process_tree(&mut child)?;
        assert!(status.success());
        assert!(matches!(
            rustix::process::waitid(
                rustix::process::WaitId::Pid(process_group),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            ),
            Err(error) if error == rustix::io::Errno::CHILD
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exit_observation_retries_interrupted_waitid() {
        let mut attempts = 0_u8;
        let observed = retry_rustix_intr(|| {
            attempts = attempts.saturating_add(1);
            if attempts < 3 {
                Err(rustix::io::Errno::INTR)
            } else {
                Ok(true)
            }
        });

        assert_eq!(observed, Ok(true));
        assert_eq!(attempts, 3);
    }

    #[cfg(unix)]
    #[test]
    fn exited_group_cleanup_accepts_only_platform_proven_kill_results() {
        assert!(exited_group_kill_result(Ok(()), false).is_ok());
        assert!(exited_group_kill_result(Err(rustix::io::Errno::SRCH), false).is_ok());

        let permission = exited_group_kill_result(Err(rustix::io::Errno::PERM), false);
        assert_eq!(
            permission.err().and_then(|error| error.raw_os_error()),
            Some(rustix::io::Errno::PERM.raw_os_error())
        );
        #[cfg(target_os = "macos")]
        assert!(
            exited_group_kill_result(Err(rustix::io::Errno::PERM), true).is_ok(),
            "Darwin EPERM requires an independent anchored-zombie absence proof"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn forced_cleanup_accepts_a_child_exit_racing_with_group_kill()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("sh");
        configure_own_process_group(&mut command);
        let mut child = command
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !child_exit_observed_without_reaping(&mut child)? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "child did not exit").into());
            }
            thread::sleep(Duration::from_millis(10));
        }

        let status = force_terminate_process_tree(&mut child)?;
        assert!(status.success());
        assert!(child_reap_confirmed(&mut child));
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn forced_cleanup_repeatedly_contains_the_natural_exit_race()
    -> Result<(), Box<dyn std::error::Error>> {
        for _ in 0..32 {
            let mut command = Command::new("sh");
            configure_own_process_group(&mut command);
            let mut child = command
                .args(["-c", "exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;

            let _ = force_terminate_process_tree(&mut child)?;
            assert!(child_reap_confirmed(&mut child));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_group_retry_requires_a_delivered_or_already_gone_direct_kill() {
        assert!(direct_kill_may_have_reached_child(&Ok(())));
        assert!(direct_kill_may_have_reached_child(&Err(io::Error::new(
            io::ErrorKind::NotFound,
            "synthetic",
        ))));
        assert!(!direct_kill_may_have_reached_child(&Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic",
        ))));
    }

    #[cfg(unix)]
    #[test]
    fn checked_app_server_shutdown_rejects_a_nonzero_exit() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 7"]);
        let mut process = AppServerProcess::spawn_command(command, Path::new("/tmp"), None)
            .map_err(|error| io::Error::other(error.to_string()))?;

        assert!(process.shutdown().is_err());
        assert!(process.reaped);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn checked_app_server_shutdown_does_not_relax_a_forced_kill()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "trap '' HUP TERM; while :; do sleep 30; done"]);
        let mut process = AppServerProcess::spawn_command(command, Path::new("/tmp"), None)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let started = Instant::now();

        assert!(process.shutdown().is_err());

        assert!(process.reaped);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "strict app-server shutdown exceeded its fixed test bound"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn completed_request_shutdown_allows_a_clean_exit_within_the_shared_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "cat >/dev/null; sleep 1; exit 0"]);
        let mut process = AppServerProcess::spawn_command(command, Path::new("/tmp"), None)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let started = Instant::now();

        process.shutdown_after_completed_request_until(
            Instant::now()
                .checked_add(Duration::from_secs(2))
                .ok_or("shutdown deadline overflowed")?,
        )?;

        assert!(process.reaped);
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "completed-request shutdown did not exercise the extended clean drain"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "completed-request shutdown exceeded its fixed test bound"
        );
        assert!(process.stdin.is_none());
        assert!(process.stdout_events.is_none());
        assert!(process.stdout_reader.is_none());
        assert!(process.stderr_drainer.is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn completed_request_shutdown_never_promotes_forced_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "trap '' HUP TERM; while :; do sleep 30; done"]);
        let mut process = AppServerProcess::spawn_command(command, Path::new("/tmp"), None)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(100))
            .ok_or("shutdown deadline overflowed")?;

        let error = match process.shutdown_after_completed_request_until(deadline) {
            Ok(()) => return Err("forced cleanup became a successful shutdown".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(process.reaped);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "forced cleanup exceeded its fixed test bound"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn completed_request_shutdown_rejects_an_expired_deadline_after_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let mut process = AppServerProcess::spawn_command(command, Path::new("/tmp"), None)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let observation_deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or("observation deadline overflowed")?;
        while !child_exit_observed_without_reaping(&mut process.child)? {
            if Instant::now() >= observation_deadline {
                return Err("child did not exit before the test deadline".into());
            }
            thread::sleep(Duration::from_millis(10));
        }

        let error = match process.shutdown_after_completed_request_until(Instant::now()) {
            Ok(()) => return Err("an expired shutdown deadline succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(process.reaped);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn completed_request_shutdown_rejects_a_signal_exit() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "cat >/dev/null; kill -TERM \"$$\""]);
        let mut process = AppServerProcess::spawn_command(command, Path::new("/tmp"), None)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or("shutdown deadline overflowed")?;

        let error = match process.shutdown_after_completed_request_until(deadline) {
            Ok(()) => return Err("a signal exit became a successful shutdown".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(process.reaped);
        Ok(())
    }

    #[cfg(unix)]
    struct PrivatePidTestRoot {
        path: PathBuf,
        identity: (u64, u64),
    }

    #[cfg(unix)]
    impl PrivatePidTestRoot {
        fn new(label: &str) -> io::Result<Self> {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

            let path = std::env::temp_dir().join(format!("cf-{label}-{}", uuid::Uuid::new_v4()));
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o7777 != 0o700
            {
                let _ = fs::remove_dir(&path);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PID test root was not private",
                ));
            }
            Ok(Self {
                path,
                identity: (metadata.dev(), metadata.ino()),
            })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    #[cfg(unix)]
    impl Drop for PrivatePidTestRoot {
        fn drop(&mut self) {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
                metadata.file_type().is_dir()
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.permissions().mode() & 0o7777 == 0o700
                    && (metadata.dev(), metadata.ino()) == self.identity
            }) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }
    }

    #[cfg(unix)]
    fn parse_published_test_pid(raw_pid: &str) -> io::Result<rustix::process::Pid> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "escaped process PID publication was not canonical",
            )
        };
        if raw_pid.is_empty()
            || raw_pid.starts_with('0')
            || !raw_pid.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(invalid());
        }
        let raw = raw_pid.parse::<i32>().map_err(|_| invalid())?;
        let pid = rustix::process::Pid::from_raw(raw).ok_or_else(invalid)?;
        if pid.as_raw_nonzero().get().to_string() != raw_pid {
            return Err(invalid());
        }
        Ok(pid)
    }

    #[cfg(unix)]
    fn read_published_test_pid(path: &Path) -> io::Result<rustix::process::Pid> {
        use std::os::fd::AsFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "escaped process PID publication was not a stable private file",
            )
        };
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "PID parent was missing"))?;
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "PID filename was missing")
        })?;
        let visible_parent = fs::symlink_metadata(parent)?;
        let directory = File::from(
            rustix::fs::open(
                parent,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        let opened_parent = directory.metadata()?;
        if !opened_parent.file_type().is_dir()
            || opened_parent.uid() != rustix::process::geteuid().as_raw()
            || opened_parent.permissions().mode() & 0o7777 != 0o700
            || opened_parent.dev() != visible_parent.dev()
            || opened_parent.ino() != visible_parent.ino()
        {
            return Err(invalid());
        }
        let mut published = File::from(
            rustix::fs::openat(
                directory.as_fd(),
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        let before = published.metadata()?;
        if !before.file_type().is_file()
            || before.uid() != rustix::process::geteuid().as_raw()
            || before.permissions().mode() & 0o7777 != 0o600
            || before.nlink() != 1
            || !(1..=10).contains(&before.len())
        {
            return Err(invalid());
        }
        let mut raw_pid = String::new();
        published.read_to_string(&mut raw_pid)?;
        let after = published.metadata()?;
        if !after.file_type().is_file()
            || after.uid() != rustix::process::geteuid().as_raw()
            || after.permissions().mode() & 0o7777 != 0o600
            || after.nlink() != 1
            || (after.dev(), after.ino()) != (before.dev(), before.ino())
            || after.len() != before.len()
            || usize::try_from(after.len()) != Ok(raw_pid.len())
        {
            return Err(invalid());
        }
        parse_published_test_pid(&raw_pid)
    }

    #[cfg(unix)]
    fn publish_test_pid_atomically(path: &Path, raw_pid: i32) -> io::Result<()> {
        publish_test_pid_atomically_with_hooks(path, raw_pid, || Ok(()), || Ok(()))
    }

    #[cfg(unix)]
    fn publish_test_pid_atomically_with_before_publish<F>(
        path: &Path,
        raw_pid: i32,
        before_publish: F,
    ) -> io::Result<()>
    where
        F: FnOnce() -> io::Result<()>,
    {
        publish_test_pid_atomically_with_hooks(path, raw_pid, before_publish, || Ok(()))
    }

    #[cfg(unix)]
    fn publish_test_pid_atomically_with_hooks<F, G>(
        path: &Path,
        raw_pid: i32,
        before_publish: F,
        after_publish: G,
    ) -> io::Result<()>
    where
        F: FnOnce() -> io::Result<()>,
        G: FnOnce() -> io::Result<()>,
    {
        use std::os::fd::AsFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let payload = raw_pid.to_string();
        parse_published_test_pid(&payload)?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "PID parent was missing"))?;
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "PID filename was missing")
        })?;
        let visible_parent = fs::symlink_metadata(parent)?;
        let directory = File::from(
            rustix::fs::open(
                parent,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        let opened_parent = directory.metadata()?;
        if !opened_parent.file_type().is_dir()
            || opened_parent.uid() != rustix::process::geteuid().as_raw()
            || opened_parent.permissions().mode() & 0o7777 != 0o700
            || opened_parent.dev() != visible_parent.dev()
            || opened_parent.ino() != visible_parent.ino()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PID publication parent was not a stable private directory",
            ));
        }
        let temporary_name = format!(".calcifer-test-pid-{}.tmp", uuid::Uuid::new_v4());
        let mut temporary = File::from(
            rustix::fs::openat(
                directory.as_fd(),
                temporary_name.as_str(),
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(io::Error::from)?,
        );
        let created = temporary.metadata()?;
        let identity = (created.dev(), created.ino());
        let mut published_to_final = false;

        let publication = (|| -> io::Result<()> {
            if !created.file_type().is_file()
                || created.uid() != rustix::process::geteuid().as_raw()
                || created.permissions().mode() & 0o7777 != 0o600
                || created.nlink() != 1
                || created.len() != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PID temporary file was not private",
                ));
            }
            temporary.write_all(payload.as_bytes())?;
            temporary.sync_all()?;
            let durable = temporary.metadata()?;
            if !durable.file_type().is_file()
                || durable.uid() != rustix::process::geteuid().as_raw()
                || durable.permissions().mode() & 0o7777 != 0o600
                || durable.nlink() != 1
                || (durable.dev(), durable.ino()) != identity
                || usize::try_from(durable.len()) != Ok(payload.len())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PID temporary file changed before publication",
                ));
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
            published_to_final = true;
            after_publish()?;
            let published = File::from(
                rustix::fs::openat(
                    directory.as_fd(),
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(io::Error::from)?,
            );
            let published_metadata = published.metadata()?;
            if !published_metadata.file_type().is_file()
                || published_metadata.uid() != rustix::process::geteuid().as_raw()
                || published_metadata.permissions().mode() & 0o7777 != 0o600
                || published_metadata.nlink() != 1
                || (published_metadata.dev(), published_metadata.ino()) != identity
                || usize::try_from(published_metadata.len()) != Ok(payload.len())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PID publication identity changed",
                ));
            }
            directory.sync_all()?;
            Ok(())
        })();

        if publication.is_err() {
            let cleanup_name = if published_to_final {
                name
            } else {
                OsStr::new(temporary_name.as_str())
            };
            if let Ok(descriptor) = rustix::fs::openat(
                directory.as_fd(),
                cleanup_name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                let candidate = File::from(descriptor);
                if candidate.metadata().is_ok_and(|metadata| {
                    metadata.file_type().is_file()
                        && metadata.uid() == rustix::process::geteuid().as_raw()
                        && metadata.permissions().mode() & 0o7777 == 0o600
                        && metadata.nlink() == 1
                        && (metadata.dev(), metadata.ino()) == identity
                }) {
                    drop(candidate);
                    let _ = rustix::fs::unlinkat(
                        directory.as_fd(),
                        cleanup_name,
                        rustix::fs::AtFlags::empty(),
                    );
                    let _ = directory.sync_all();
                }
            }
        }
        publication
    }

    #[cfg(unix)]
    fn expect_pid_publication_collision(path: &Path) -> io::Result<()> {
        match publish_test_pid_atomically(path, 43) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("PID collision returned an unexpected error: {error}"),
            )),
            Ok(()) => Err(io::Error::other(
                "PID publication replaced a pre-existing filesystem node",
            )),
        }
    }

    #[cfg(unix)]
    #[test]
    fn completed_request_shutdown_bounds_a_background_pipe_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let escaped_root = PrivatePidTestRoot::new("app-server-escaped-pid")?;
        let escaped_pid_file = escaped_root.path().join("pid");
        let helper = fs::canonicalize(std::env::current_exe()?)?;
        let mut command = Command::new("/bin/sh");
        command
            .env("CALCIFER_TEST_ESCAPED_HELPER", helper)
            .env("CALCIFER_TEST_ESCAPED_PID_FILE", &escaped_pid_file)
            .args([
                "-c",
                "( \"$CALCIFER_TEST_ESCAPED_HELPER\" providers::codex::tests::completed_request_shutdown_escaped_pipe_owner_helper --exact --ignored --nocapture; : ) & cat >/dev/null; exit 0",
            ]);
        let mut process = AppServerProcess::spawn_command(command, Path::new("/tmp"), None)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let pid_file_deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or("PID-file deadline overflowed")?;
        let escaped_pid = loop {
            match read_published_test_pid(&escaped_pid_file) {
                Ok(pid) => break pid,
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && Instant::now() < pid_file_deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        };
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(200))
            .ok_or("shutdown deadline overflowed")?;

        let shutdown = process.shutdown_after_completed_request_until(deadline);
        let escaped_cleanup =
            rustix::process::kill_process(escaped_pid, rustix::process::Signal::KILL);
        fs::remove_file(&escaped_pid_file)?;
        let error = match shutdown {
            Ok(()) => return Err("a background pipe owner escaped the shutdown deadline".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(process.reaped);
        assert!(process.stdout_reader.is_none());
        assert!(process.stderr_drainer.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "background pipe ownership exceeded the fixed shutdown bound"
        );
        assert!(matches!(
            escaped_cleanup,
            Ok(()) | Err(rustix::io::Errno::SRCH)
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "internal subprocess for escaped pipe-owner containment"]
    fn completed_request_shutdown_escaped_pipe_owner_helper()
    -> Result<(), Box<dyn std::error::Error>> {
        let pid_file = std::env::var_os("CALCIFER_TEST_ESCAPED_PID_FILE")
            .map(PathBuf::from)
            .ok_or("escaped pipe-owner helper was not explicitly requested")?;
        rustix::process::setsid()?;
        publish_test_pid_atomically(&pid_file, rustix::process::getpid().as_raw_nonzero().get())?;
        println!("pipe-held");
        io::stdout().flush()?;
        thread::sleep(Duration::from_secs(30));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn escaped_pipe_owner_pid_publication_is_atomic_canonical_and_no_replace()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PrivatePidTestRoot::new("atomic-test-pid")?;
        let pid_file = root.path().join("pid");
        publish_test_pid_atomically_with_before_publish(
            &pid_file,
            42,
            || match fs::read_to_string(&pid_file) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Ok(_) => Err(io::Error::other(
                    "the final PID path became visible before complete publication",
                )),
                Err(error) => Err(error),
            },
        )?;

        assert_eq!(fs::read_to_string(&pid_file)?, "42");
        assert_eq!(
            read_published_test_pid(&pid_file)?.as_raw_nonzero().get(),
            42
        );
        for malformed in ["", "0", "0012", "+12", "-12", "12\n", "private"] {
            let error = match parse_published_test_pid(malformed) {
                Ok(pid) => {
                    return Err(format!(
                        "malformed PID publication was accepted as {}: {malformed:?}",
                        pid.as_raw_nonzero()
                    )
                    .into());
                }
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "malformed PID publication was accepted: {malformed:?}"
            );
        }

        expect_pid_publication_collision(&pid_file)?;
        assert_eq!(fs::read_to_string(&pid_file)?, "42");
        fs::remove_file(pid_file)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn failed_post_rename_pid_publication_removes_only_its_owned_inode()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = PrivatePidTestRoot::new("post-rename-test-pid")?;
        let pid_file = root.path().join("pid");
        let failure = match publish_test_pid_atomically_with_hooks(
            &pid_file,
            42,
            || Ok(()),
            || Err(io::Error::other("injected post-rename publication failure")),
        ) {
            Ok(()) => return Err("injected post-rename failure unexpectedly succeeded".into()),
            Err(error) => error,
        };

        assert_eq!(failure.kind(), io::ErrorKind::Other);
        match fs::symlink_metadata(&pid_file) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err("failed publication left the final PID inode visible".into()),
            Err(error) => return Err(error.into()),
        }
        if fs::read_dir(root.path())?.next().is_some() {
            return Err("failed publication left a PID temporary inode behind".into());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pid_publication_refuses_preexisting_ambiguous_filesystem_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{
            DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt, symlink,
        };
        use std::os::unix::net::UnixListener;

        let root = PrivatePidTestRoot::new("nodes")?;
        let sentinel = root.path().join("sentinel");
        let mut sentinel_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&sentinel)?;
        sentinel_file.write_all(b"sentinel")?;
        sentinel_file.sync_all()?;

        let symlink_path = root.path().join("symlink");
        symlink(&sentinel, &symlink_path)?;
        expect_pid_publication_collision(&symlink_path)?;
        assert!(
            fs::symlink_metadata(&symlink_path)?
                .file_type()
                .is_symlink()
        );
        if read_published_test_pid(&symlink_path).is_ok() {
            return Err("PID reader accepted a symlink publication".into());
        }

        let directory_path = root.path().join("directory");
        fs::DirBuilder::new().mode(0o700).create(&directory_path)?;
        expect_pid_publication_collision(&directory_path)?;
        if read_published_test_pid(&directory_path).is_ok() {
            return Err("PID reader accepted a directory publication".into());
        }

        let hardlink_path = root.path().join("hardlink");
        fs::hard_link(&sentinel, &hardlink_path)?;
        expect_pid_publication_collision(&hardlink_path)?;
        if read_published_test_pid(&hardlink_path).is_ok() {
            return Err("PID reader accepted a multiply-linked publication".into());
        }

        let wrong_mode_path = root.path().join("wrong-mode");
        fs::write(&wrong_mode_path, b"42")?;
        fs::set_permissions(&wrong_mode_path, fs::Permissions::from_mode(0o644))?;
        expect_pid_publication_collision(&wrong_mode_path)?;
        if read_published_test_pid(&wrong_mode_path).is_ok() {
            return Err("PID reader accepted a wrong-mode publication".into());
        }

        let socket_path = root.path().join("socket");
        let socket = UnixListener::bind(&socket_path)?;
        expect_pid_publication_collision(&socket_path)?;
        assert!(fs::symlink_metadata(&socket_path)?.file_type().is_socket());
        if read_published_test_pid(&socket_path).is_ok() {
            return Err("PID reader accepted a socket publication".into());
        }
        drop(socket);

        assert_eq!(fs::read_to_string(&sentinel)?, "sentinel");
        Ok(())
    }

    #[test]
    fn io_worker_completion_notification_does_not_bypass_the_join_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let (completed_sender, completed) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            let _ = completed_sender.send(Instant::now());
            thread::sleep(Duration::from_millis(500));
        });
        let worker = AppServerIoWorker { handle, completed };
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(100))
            .ok_or("worker deadline overflowed")?;

        let error = match worker.join_until(deadline) {
            Ok(()) => return Err("an unfinished I/O worker bypassed its join deadline".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "I/O worker join exceeded its fixed test bound"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_kills_a_descendant_that_keeps_stdout_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "(trap '' HUP TERM; sleep 30) & printf 'codex-cli 0.144.4\\n'; exit 0",
        ]);
        let started = Instant::now();

        let version = probe_codex_version_command(
            command,
            Path::new("/tmp"),
            Instant::now() + Duration::from_secs(2),
            None,
        )?;

        assert_eq!(version, "0.144.4");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the inherited stdout descriptor must not stall the reader join"
        );
        Ok(())
    }

    #[test]
    fn version_probe_does_not_spawn_after_absolute_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonexistent_executable = std::env::temp_dir().join(format!(
            "calcifer-expired-version-probe-{}",
            uuid::Uuid::new_v4()
        ));
        let working_directory = std::env::temp_dir();
        assert!(!nonexistent_executable.exists());

        // Attempting to spawn this missing executable deterministically returns
        // `Spawn`, so `Timeout` proves the deadline guard ran before OS spawn.
        let failure = match probe_codex_version_command_with_origin(
            Command::new(&nonexistent_executable),
            &working_directory,
            Instant::now(),
            None,
        ) {
            Err(failure) => failure,
            Ok(_) => return Err("an expired version probe unexpectedly succeeded".into()),
        };

        assert_eq!(failure.error(), CodexThreadError::Timeout);
        assert_eq!(
            failure.timeout_origin(),
            Some(CodexVersionProbeTimeoutOrigin::ChildExit)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_reports_child_exit_timeout_origin() -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "trap '' HUP TERM; sleep 30"]);
        let started = Instant::now();

        let failure = match probe_codex_version_command_with_origin(
            command,
            Path::new("/tmp"),
            Instant::now() + Duration::from_millis(100),
            None,
        ) {
            Err(failure) => failure,
            Ok(_) => return Err("the non-exiting version child did not time out".into()),
        };

        assert_eq!(failure.error(), CodexThreadError::Timeout);
        assert_eq!(
            failure.timeout_origin(),
            Some(CodexVersionProbeTimeoutOrigin::ChildExit)
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "child-exit cleanup exceeded its fixed test bound"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_reports_stdout_drain_timeout_origin() -> Result<(), Box<dyn std::error::Error>>
    {
        let escaped_root = PrivatePidTestRoot::new("version-escaped-pid")?;
        let escaped_pid_file = escaped_root.path().join("pid");
        let helper = fs::canonicalize(std::env::current_exe()?)?;
        let mut command = Command::new("/bin/sh");
        command
            .env("CALCIFER_TEST_ESCAPED_HELPER", helper)
            .env("CALCIFER_TEST_ESCAPED_PID_FILE", &escaped_pid_file)
            .args([
                "-c",
                "( \"$CALCIFER_TEST_ESCAPED_HELPER\" providers::codex::tests::version_probe_escaped_stdout_owner_helper --exact --ignored --nocapture; : ) & while [ ! -s \"$CALCIFER_TEST_ESCAPED_PID_FILE\" ]; do sleep 0.01; done; printf 'codex-cli 0.144.4\\n'; exit 0",
            ]);
        let started = Instant::now();

        let result = probe_codex_version_command_with_origin(
            command,
            Path::new("/tmp"),
            Instant::now() + Duration::from_millis(300),
            None,
        );
        let escaped_pid = read_published_test_pid(&escaped_pid_file)?;
        let escaped_cleanup =
            rustix::process::kill_process(escaped_pid, rustix::process::Signal::KILL);
        fs::remove_file(&escaped_pid_file)?;
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => return Err("an escaped stdout owner did not time out the drain".into()),
        };

        assert_eq!(failure.error(), CodexThreadError::Timeout);
        assert_eq!(
            failure.timeout_origin(),
            Some(CodexVersionProbeTimeoutOrigin::StdoutDrain)
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "stdout-drain detection exceeded its fixed test bound"
        );
        assert!(matches!(
            escaped_cleanup,
            Ok(()) | Err(rustix::io::Errno::SRCH)
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "internal subprocess for escaped version-pipe containment"]
    fn version_probe_escaped_stdout_owner_helper() -> Result<(), Box<dyn std::error::Error>> {
        let pid_file = std::env::var_os("CALCIFER_TEST_ESCAPED_PID_FILE")
            .map(PathBuf::from)
            .ok_or("escaped version helper was not explicitly requested")?;
        rustix::process::setsid()?;
        publish_test_pid_atomically(&pid_file, rustix::process::getpid().as_raw_nonzero().get())?;
        thread::sleep(Duration::from_secs(30));
        Ok(())
    }

    #[test]
    fn rollout_scan_cap_boundary_is_strictly_below_upstream_limit() {
        assert!(rollout_count_is_below_cap(9_999, 10_000));
        assert!(!rollout_count_is_below_cap(10_000, 10_000));
    }

    #[cfg(unix)]
    #[test]
    fn rollout_snapshots_are_per_root_and_normalize_missing_empty_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let home = std::env::temp_dir().join(format!(
            "calcifer-rollout-snapshot-roots-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&home)?;
        let missing = snapshot_rollout_store_with_limits(&home, 3, 32)?;
        for root in [home.join("sessions"), home.join("archived_sessions")] {
            fs::DirBuilder::new().mode(0o700).create(root)?;
        }
        let empty = snapshot_rollout_store_with_limits(&home, 3, 32)?;
        assert_eq!(missing, empty);

        let active_dir = home.join("sessions/2026/07/15");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&active_dir)?;
        for path in [
            active_dir.join("one.jsonl"),
            active_dir.join("two.jsonl"),
            home.join("archived_sessions/one.jsonl"),
            home.join("archived_sessions/two.jsonl"),
        ] {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        let below = snapshot_rollout_store_with_limits(&home, 3, 32)?;
        assert!(below.active.complete);
        assert!(below.archived.complete);

        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(active_dir.join("three.jsonl"))?;
        let capped = snapshot_rollout_store_with_limits(&home, 3, 32)?;
        assert!(!capped.active.complete);
        assert!(capped.archived.complete);

        fs::remove_dir_all(home)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rollout_snapshot_detects_replacement_and_in_place_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sandbox = std::env::temp_dir().join(format!(
            "calcifer-rollout-snapshot-mutation-{}-{nonce}",
            std::process::id()
        ));
        let home = sandbox.join("home");
        let active = home.join("sessions/2026/07/15/thread.jsonl");
        let archived = home.join("archived_sessions/thread.jsonl");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(active.parent().unwrap_or(&home))?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(archived.parent().unwrap_or(&home))?;
        for path in [&active, &archived] {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(b"one")?;
        }
        let before = snapshot_rollout_store_with_limits(&home, 10, 64)?;

        let displaced = sandbox.join("displaced.jsonl");
        fs::rename(&active, &displaced)?;
        let mut replacement = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&active)?;
        replacement.write_all(b"one")?;
        replacement.sync_all()?;
        let replaced = snapshot_rollout_store_with_limits(&home, 10, 64)?;
        assert_ne!(before.active, replaced.active);

        let mut archived_file = fs::OpenOptions::new().append(true).open(&archived)?;
        archived_file.write_all(b"-changed")?;
        archived_file.sync_all()?;
        let mutated = snapshot_rollout_store_with_limits(&home, 10, 64)?;
        assert_ne!(replaced.archived, mutated.archived);

        fs::remove_dir_all(sandbox)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rollout_snapshot_rejects_symlink_and_unreadable_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let home = std::env::temp_dir().join(format!(
            "calcifer-rollout-snapshot-unsafe-{}-{nonce}",
            std::process::id()
        ));
        let sessions = home.join("sessions");
        let archived = home.join("archived_sessions");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&sessions)?;
        fs::DirBuilder::new().mode(0o700).create(&archived)?;
        symlink(&archived, sessions.join("linked"))?;
        assert_eq!(
            snapshot_rollout_store_with_limits(&home, 10, 64),
            Err(CodexThreadError::SessionSchema)
        );
        fs::remove_file(sessions.join("linked"))?;

        let unreadable = archived.join("unreadable");
        fs::DirBuilder::new().mode(0o700).create(&unreadable)?;
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))?;
        assert_eq!(
            snapshot_rollout_store_with_limits(&home, 10, 64),
            Err(CodexThreadError::SessionSchema)
        );
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700))?;

        fs::remove_dir_all(home)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rollout_snapshot_accepts_legacy_readable_modes_but_rejects_writable_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let home = std::env::temp_dir().join(format!(
            "calcifer-rollout-snapshot-modes-{}-{nonce}",
            std::process::id()
        ));
        let sessions = home.join("sessions");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&sessions)?;
        let rollout = sessions.join("legacy.jsonl");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&rollout)?;

        fs::set_permissions(&sessions, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&rollout, fs::Permissions::from_mode(0o644))?;
        assert!(snapshot_rollout_store_with_limits(&home, 10, 64)?.complete());

        fs::set_permissions(&rollout, fs::Permissions::from_mode(0o666))?;
        assert_eq!(
            snapshot_rollout_store_with_limits(&home, 10, 64),
            Err(CodexThreadError::SessionSchema)
        );
        fs::set_permissions(&rollout, fs::Permissions::from_mode(0o644))?;
        fs::set_permissions(&sessions, fs::Permissions::from_mode(0o777))?;
        assert_eq!(
            snapshot_rollout_store_with_limits(&home, 10, 64),
            Err(CodexThreadError::SessionSchema)
        );
        fs::set_permissions(&sessions, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            snapshot_rollout_store_with_limits(&home, 10, 64),
            Err(CodexThreadError::SessionSchema),
            "nested legacy modes are safe only behind a private managed home"
        );

        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        fs::remove_dir_all(home)?;
        Ok(())
    }

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
            "CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE",
            "CALCIFER_INTERNAL_CODEX_PROFILE_ID",
            "CALCIFER_INTERNAL_CODEX_THREAD_ID",
            "CALCIFER_INTERNAL_CODEX_EXECUTABLE",
            "CALCIFER_INTERNAL_CODEX_FOREGROUND_PROCESS_GROUP",
            "CALCIFER_SUPERVISOR_READINESS_FD",
            "CALCIFER_PACKAGE_SUPERVISOR_ROLE",
            "CALCIFER_PACKAGE_TUI_LAUNCHER",
            "CaLcIfEr_PaCkAgE_FuTuRe_CoNtRoL",
            "CALCIFER_CODEX_COMPAT_BINARY",
            "CALCIFER_HOME",
            "CaLcIfEr_FuTuRe_CoNtRoL",
            "OPENAI_API_KEY",
            "OPENAI_FUTURE_ENDPOINT",
            "OpEnAi_FuTuRe_RoUtInG_SeCrEt",
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
    fn managed_command_projects_the_complete_safe_ambient_environment() {
        let command = managed_command(
            Path::new("/synthetic/codex"),
            Path::new("/synthetic/profile"),
        );
        let projected = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
            .collect::<BTreeMap<std::ffi::OsString, Option<std::ffi::OsString>>>();
        let mut safe_values = 0_usize;
        for (name, value) in std::env::vars_os() {
            if name == OsStr::new("CODEX_HOME") || is_managed_environment_override(&name) {
                continue;
            }
            safe_values += 1;
            assert_eq!(
                projected.get(&name),
                Some(&Some(value)),
                "safe ambient environment must survive the launcher projection"
            );
        }
        assert!(
            safe_values > 0,
            "the test process had no safe ambient values"
        );
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
        assert_eq!(
            parse_codex_version("calcifer/0.145.0-alpha.11 (synthetic test)"),
            Some("0.145.0-alpha.11".to_owned())
        );
        assert_eq!(
            parse_codex_version("calcifer/0.145.0+build.01 (synthetic test)"),
            Some("0.145.0+build.01".to_owned())
        );

        for user_agent in [
            "codex-cli/0.144.4",
            "calcifer/00.144.4",
            "calcifer/0.0144.4",
            "calcifer/0.144.04",
            "calcifer/0.144.4-beta.01",
            "calcifer/0.144.4-beta..1",
            "calcifer/0.144.4+build+again",
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
            None,
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

        let mut exact_total = CappedReader::new(Cursor::new(vec![b'd'; 4]), 4);
        let mut exact_bytes = Vec::new();
        exact_total.read_to_end(&mut exact_bytes)?;
        assert_eq!(exact_bytes, vec![b'd'; 4]);

        let mut oversized_total = CappedReader::new(Cursor::new(vec![b'e'; 5]), 4);
        let mut bounded_bytes = Vec::new();
        let total_error = oversized_total
            .read_to_end(&mut bounded_bytes)
            .err()
            .ok_or_else(|| io::Error::other("oversized rollout must fail"))?;
        assert_eq!(total_error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(bounded_bytes, vec![b'e'; 4]);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn thread_projection_and_lifecycle_ignore_provider_content()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

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
        std::fs::set_permissions(&sessions, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(&rollout, std::fs::Permissions::from_mode(0o644))?;

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
            validate_thread_projection(wire, &canonical_workspace, &home, "0.144.4", Some(false))
                .map_err(|error| io::Error::other(format!("projection failed: {error:?}")))?;
        assert!(
            snapshot_rollout_store_with_limits(&home, 10, 64)
                .map_err(|error| io::Error::other(format!("snapshot failed: {error:?}")))?
                .matches_thread(&metadata),
            "wire metadata must map to the stable rollout snapshot without persisting its path"
        );
        let lifecycle = inspect_rollout_lifecycle(&metadata, &canonical_workspace)
            .map_err(|error| io::Error::other(format!("lifecycle failed: {error:?}")))?;

        assert_eq!(metadata.thread_id, thread_id);
        assert_eq!(
            metadata.rollout_fingerprint.length,
            std::fs::metadata(&rollout)?.len()
        );
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

        let replaced_rollout = sessions.join("replaced-rollout.jsonl");
        std::fs::rename(&rollout, &replaced_rollout)?;
        let mut replacement_options = std::fs::OpenOptions::new();
        replacement_options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&rollout)?
            .write_all(b"{}\n")?;
        assert_eq!(
            inspect_rollout_lifecycle(&metadata, &canonical_workspace)
                .err()
                .ok_or_else(|| io::Error::other("replaced rollout inode was accepted"))?,
            CodexThreadError::SessionSchema
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
