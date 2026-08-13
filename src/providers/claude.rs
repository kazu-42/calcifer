//! Linux-only Claude Code profile compatibility boundary.

#![allow(dead_code)] // Public profile lifecycle wiring follows this sealed adapter gate.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

const SUPPORTED_VERSION_OUTPUT: &str = "2.1.227 (Claude Code)";
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;

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
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
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

#[cfg(unix)]
pub(crate) fn validate_linux_credentials(config_dir: &Path) -> Result<(), ClaudeProfileError> {
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
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(ClaudeProfileError::Credentials);
    }
    Ok(())
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
