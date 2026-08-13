//! Linux-only Claude Code profile compatibility boundary.

#![allow(dead_code)] // Public profile lifecycle wiring follows this sealed adapter gate.

use std::ffi::OsStr;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

const SUPPORTED_VERSION_OUTPUT: &str = "2.1.227 (Claude Code)";
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const MAX_STATUS_BYTES: usize = 16 * 1024;
const MAX_VERSION_BYTES: usize = 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaudeAuthStatus {
    pub(crate) auth_method: String,
    pub(crate) api_provider: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClaudeProfileError {
    UnsupportedVersion,
    Unauthenticated,
    StatusSchema,
    Credentials,
    Io,
}

impl ClaudeProfileError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "claude_version_unsupported",
            Self::Unauthenticated => "claude_unauthenticated",
            Self::StatusSchema => "claude_status_unsupported",
            Self::Credentials => "claude_credentials_invalid",
            Self::Io => "claude_io_error",
        }
    }

    pub(crate) const fn safe_message(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => {
                "The installed Claude Code version is outside Calcifer's reviewed compatibility boundary."
            }
            Self::Unauthenticated => {
                "The selected Claude profile is not authenticated through the official CLI."
            }
            Self::StatusSchema => {
                "Claude Code returned an unsupported authentication status contract."
            }
            Self::Credentials => {
                "The managed Claude credential file failed Calcifer's Linux ownership or permission checks."
            }
            Self::Io => "Calcifer could not inspect the managed Claude profile.",
        }
    }
}

impl fmt::Display for ClaudeProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for ClaudeProfileError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClaudeAuthStatusDocument {
    logged_in: bool,
    auth_method: String,
    api_provider: String,
}

pub(crate) fn managed_command(executable: &Path, config_dir: &Path) -> Command {
    let mut command = Command::new(executable);
    for (name, _) in std::env::vars_os() {
        if conflicts_with_managed_profile(&name) {
            command.env_remove(name);
        }
    }
    command.env("CLAUDE_CONFIG_DIR", config_dir);
    command
}

fn conflicts_with_managed_profile(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return true;
    };
    name.starts_with("ANTHROPIC_")
        || name.starts_with("CLAUDE_")
        || matches!(
            name,
            "AWS_ACCESS_KEY_ID"
                | "AWS_SECRET_ACCESS_KEY"
                | "AWS_SESSION_TOKEN"
                | "AWS_PROFILE"
                | "GOOGLE_APPLICATION_CREDENTIALS"
                | "CLOUD_ML_REGION"
                | "VERTEX_REGION_CLAUDE_3_5_HAIKU"
                | "VERTEX_REGION_CLAUDE_3_5_SONNET"
                | "VERTEX_REGION_CLAUDE_3_7_SONNET"
                | "VERTEX_REGION_CLAUDE_4_0_OPUS"
                | "VERTEX_REGION_CLAUDE_4_0_SONNET"
                | "VERTEX_REGION_CLAUDE_4_1_OPUS"
                | "VERTEX_REGION_CLAUDE_4_5_HAIKU"
                | "VERTEX_REGION_CLAUDE_4_5_OPUS"
                | "VERTEX_REGION_CLAUDE_4_5_SONNET"
        )
}

pub(crate) fn validate_version_output(output: &[u8]) -> Result<(), ClaudeProfileError> {
    if output == format!("{SUPPORTED_VERSION_OUTPUT}\n").as_bytes() {
        Ok(())
    } else {
        Err(ClaudeProfileError::UnsupportedVersion)
    }
}

pub(crate) fn parse_auth_status(bytes: &[u8]) -> Result<ClaudeAuthStatus, ClaudeProfileError> {
    if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
        return Err(ClaudeProfileError::StatusSchema);
    }
    let document: ClaudeAuthStatusDocument =
        serde_json::from_slice(bytes).map_err(|_| ClaudeProfileError::StatusSchema)?;
    if !document.logged_in
        || document.auth_method.is_empty()
        || document.api_provider != "firstParty"
        || document.auth_method.len() > 64
        || !document.auth_method.is_ascii()
    {
        return Err(if document.logged_in {
            ClaudeProfileError::StatusSchema
        } else {
            ClaudeProfileError::Unauthenticated
        });
    }
    Ok(ClaudeAuthStatus {
        auth_method: document.auth_method,
        api_provider: document.api_provider,
    })
}

pub(crate) fn verify_profile(
    executable: &Path,
    config_dir: &Path,
    working_directory: &Path,
) -> Result<ClaudeAuthStatus, ClaudeProfileError> {
    let mut version = managed_command(executable, config_dir);
    version.arg("--version").current_dir(working_directory);
    let (status, output) = bounded_stdout(version, MAX_VERSION_BYTES)?;
    if !status.success() {
        return Err(ClaudeProfileError::UnsupportedVersion);
    }
    validate_version_output(&output)?;

    let mut auth = managed_command(executable, config_dir);
    auth.args(["auth", "status", "--json"])
        .current_dir(working_directory);
    let (command_status, output) = bounded_stdout(auth, MAX_STATUS_BYTES)?;
    if !command_status.success() {
        return Err(ClaudeProfileError::Unauthenticated);
    }
    let status = parse_auth_status(&output)?;
    validate_linux_credentials(config_dir)?;
    Ok(status)
}

fn bounded_stdout(
    command: Command,
    maximum_bytes: usize,
) -> Result<(std::process::ExitStatus, Vec<u8>), ClaudeProfileError> {
    bounded_stdout_until(command, maximum_bytes, Instant::now() + PROBE_TIMEOUT)
}

fn bounded_stdout_until(
    mut command: Command,
    maximum_bytes: usize,
    deadline: Instant,
) -> Result<(std::process::ExitStatus, Vec<u8>), ClaudeProfileError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    super::codex::configure_own_process_group(&mut command);
    let mut child = command.spawn().map_err(|_| ClaudeProfileError::Io)?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = super::codex::force_terminate_process_tree(&mut child);
            return Err(ClaudeProfileError::Io);
        }
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = match thread::Builder::new()
        .name("calcifer-claude-probe".to_owned())
        .spawn(move || {
            let mut output = Vec::new();
            let result = stdout
                .take((maximum_bytes + 1) as u64)
                .read_to_end(&mut output)
                .map(|_| output);
            let _ = sender.send(result);
        }) {
        Ok(reader) => reader,
        Err(_) => {
            let _ = super::codex::force_terminate_process_tree(&mut child);
            return Err(ClaudeProfileError::Io);
        }
    };
    let status = loop {
        match super::codex::child_exit_observed_without_reaping(&mut child) {
            Ok(true) => {
                break super::codex::reap_exited_process_tree(&mut child)
                    .map_err(|_| ClaudeProfileError::Io)?;
            }
            Ok(false) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(false) | Err(_) => {
                let _ = super::codex::force_terminate_process_tree(&mut child);
                drop(reader);
                return Err(ClaudeProfileError::Io);
            }
        }
    };
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        drop(reader);
        return Err(ClaudeProfileError::Io);
    };
    let output = match receiver.recv_timeout(remaining) {
        Ok(Ok(output)) => output,
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected | RecvTimeoutError::Timeout) => {
            drop(reader);
            return Err(ClaudeProfileError::Io);
        }
    };
    reader.join().map_err(|_| ClaudeProfileError::Io)?;
    if output.len() > maximum_bytes {
        return Err(ClaudeProfileError::StatusSchema);
    }
    Ok((status, output))
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_linux_credentials(config_dir: &Path) -> Result<(), ClaudeProfileError> {
    open_validated_linux_credentials(config_dir).map(|_| ())
}

#[cfg(target_os = "linux")]
pub(crate) fn sync_linux_credentials(config_dir: &Path) -> Result<(), ClaudeProfileError> {
    let credentials = open_validated_linux_credentials(config_dir)?;
    credentials.sync_all().map_err(|_| ClaudeProfileError::Io)?;
    std::fs::File::open(config_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ClaudeProfileError::Io)
}

#[cfg(target_os = "linux")]
fn open_validated_linux_credentials(
    config_dir: &Path,
) -> Result<std::fs::File, ClaudeProfileError> {
    use std::os::unix::fs::MetadataExt;

    let canonical = std::fs::canonicalize(config_dir).map_err(|_| ClaudeProfileError::Io)?;
    if canonical != config_dir {
        return Err(ClaudeProfileError::Credentials);
    }
    let root = std::fs::symlink_metadata(config_dir).map_err(|_| ClaudeProfileError::Io)?;
    if !root.is_dir()
        || root.file_type().is_symlink()
        || root.uid() != rustix::process::getuid().as_raw()
        || root.mode() & 0o077 != 0
    {
        return Err(ClaudeProfileError::Credentials);
    }
    let credentials = config_dir.join(".credentials.json");
    let metadata =
        std::fs::symlink_metadata(&credentials).map_err(|_| ClaudeProfileError::Credentials)?;
    let file = std::fs::File::open(&credentials).map_err(|_| ClaudeProfileError::Credentials)?;
    let opened = file
        .metadata()
        .map_err(|_| ClaudeProfileError::Credentials)?;
    let current =
        std::fs::symlink_metadata(&credentials).map_err(|_| ClaudeProfileError::Credentials)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || !current.is_file()
        || current.file_type().is_symlink()
        || !opened.is_file()
        || metadata.dev() != opened.dev()
        || metadata.ino() != opened.ino()
        || current.dev() != opened.dev()
        || current.ino() != opened.ino()
        || opened.uid() != rustix::process::getuid().as_raw()
        || opened.mode() & 0o777 != 0o600
        || opened.nlink() != 1
        || opened.len() == 0
        || opened.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(ClaudeProfileError::Credentials);
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn validate_linux_credentials(_config_dir: &Path) -> Result<(), ClaudeProfileError> {
    Err(ClaudeProfileError::Credentials)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sync_linux_credentials(_config_dir: &Path) -> Result<(), ClaudeProfileError> {
    Err(ClaudeProfileError::Credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_requires_authenticated_first_party_exact_schema() {
        let status = parse_auth_status(
            br#"{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty"}"#,
        );
        assert_eq!(
            status,
            Ok(ClaudeAuthStatus {
                auth_method: "claude.ai".to_owned(),
                api_provider: "firstParty".to_owned(),
            })
        );
        assert_eq!(
            parse_auth_status(
                br#"{"loggedIn":false,"authMethod":"none","apiProvider":"firstParty"}"#,
            ),
            Err(ClaudeProfileError::Unauthenticated)
        );
        assert_eq!(
            parse_auth_status(
                br#"{"loggedIn":true,"authMethod":"apiKey","apiProvider":"bedrock"}"#,
            ),
            Err(ClaudeProfileError::StatusSchema)
        );
        assert_eq!(
            parse_auth_status(
                br#"{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","token":"secret"}"#,
            ),
            Err(ClaudeProfileError::StatusSchema)
        );
    }

    #[test]
    fn version_gate_is_exact() {
        assert_eq!(validate_version_output(b"2.1.227 (Claude Code)\n"), Ok(()));
        assert_eq!(
            validate_version_output(b"2.1.228 (Claude Code)\n"),
            Err(ClaudeProfileError::UnsupportedVersion)
        );
    }

    #[cfg(unix)]
    #[test]
    fn provider_probe_timeout_reaps_its_process_group() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]);
        let started = Instant::now();
        assert_eq!(
            bounded_stdout_until(
                command,
                MAX_STATUS_BYTES,
                started + Duration::from_millis(100),
            ),
            Err(ClaudeProfileError::Io)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credentials_require_private_single_link_regular_file()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("calcifer-claude-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let root = std::fs::canonicalize(root)?;
        let credentials = root.join(".credentials.json");
        std::fs::write(&credentials, b"synthetic-not-a-token")?;
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(validate_linux_credentials(&root), Ok(()));

        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            validate_linux_credentials(&root),
            Err(ClaudeProfileError::Credentials)
        );
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600))?;
        let extra_link = root.join("credential-copy");
        std::fs::hard_link(&credentials, &extra_link)?;
        assert_eq!(
            validate_linux_credentials(&root),
            Err(ClaudeProfileError::Credentials)
        );
        std::fs::remove_file(extra_link)?;
        assert_eq!(sync_linux_credentials(&root), Ok(()));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn conflicting_environment_names_are_complete_and_nonsecret() {
        for name in [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_BASE_URL",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "CLAUDE_CODE_USE_FOUNDRY",
            "CLAUDE_CONFIG_DIR",
            "AWS_PROFILE",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ] {
            assert!(conflicts_with_managed_profile(OsStr::new(name)), "{name}");
        }
        assert!(!conflicts_with_managed_profile(OsStr::new("TERM")));
    }

    #[test]
    fn managed_command_sets_selected_config() {
        let command = managed_command(Path::new("/bin/echo"), Path::new("/private/profile"));
        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            environment.get(OsStr::new("CLAUDE_CONFIG_DIR")),
            Some(&Some(OsStr::new("/private/profile").to_owned()))
        );
    }
}
