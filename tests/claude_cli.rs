#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn calcifer() -> Command {
    Command::new(env!("CARGO_BIN_EXE_calcifer"))
}

fn fixture() -> Result<(std::path::PathBuf, std::ffi::OsString), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-claude-cli-{}-{nonce}",
        std::process::id()
    ));
    let bin = sandbox.join("bin");
    std::fs::create_dir_all(&bin)?;
    std::fs::set_permissions(&sandbox, std::fs::Permissions::from_mode(0o700))?;
    let executable = bin.join("claude");
    std::fs::write(
        &executable,
        r#"#!/bin/sh
set -eu
[ "${ANTHROPIC_API_KEY+x}" != "x" ]
[ "${ANTHROPIC_AUTH_TOKEN+x}" != "x" ]
[ "${CLAUDE_CODE_USE_BEDROCK+x}" != "x" ]
[ "${AWS_PROFILE+x}" != "x" ]
[ "${GOOGLE_APPLICATION_CREDENTIALS+x}" != "x" ]
[ -n "${CLAUDE_CONFIG_DIR:-}" ]
case "${1:-}" in
  --version)
    printf '2.1.227 (Claude Code)\n'
    ;;
  auth)
    case "${2:-}" in
      login)
        umask 077
        printf '{"synthetic":"%s"}\n' "${FAKE_CLAUDE_CREDENTIAL:-initial}" > "$CLAUDE_CONFIG_DIR/.credentials.json"
        if [ "${FAKE_CLAUDE_LOGIN_EXIT:-0}" != "0" ]; then
          exit "$FAKE_CLAUDE_LOGIN_EXIT"
        fi
        ;;
      status)
        [ "${3:-}" = "--json" ]
        printf '{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty"}\n'
        exit "${FAKE_CLAUDE_STATUS_EXIT:-0}"
        ;;
      *) exit 92 ;;
    esac
    ;;
  *)
    printf '%s\n' "$*" >> "$FAKE_CLAUDE_LOG"
    exit "${FAKE_CLAUDE_RUN_EXIT:-0}"
    ;;
esac
"#,
    )?;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
    Ok((sandbox, std::env::join_paths([bin])?))
}

fn configured(root: &std::path::Path, path: &std::ffi::OsStr) -> Command {
    let mut command = calcifer();
    command
        .env("PATH", path)
        .env("CALCIFER_HOME", root)
        .env("ANTHROPIC_API_KEY", "must-not-reach-provider")
        .env("ANTHROPIC_AUTH_TOKEN", "must-not-reach-provider")
        .env("CLAUDE_CODE_USE_BEDROCK", "1")
        .env("AWS_PROFILE", "must-not-reach-provider")
        .env("GOOGLE_APPLICATION_CREDENTIALS", "/must/not/reach/provider");
    command
}

#[test]
fn claude_add_list_verify_run_rename_and_remove_use_one_private_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let (sandbox, path) = fixture()?;
    let root = sandbox.join("state");
    let log = sandbox.join("claude.log");

    let add = configured(&root, &path)
        .env("FAKE_CLAUDE_LOG", &log)
        .args(["auth", "add", "claude", "work"])
        .output()?;
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );

    let list = configured(&root, &path)
        .args(["--json", "auth", "list"])
        .output()?;
    assert!(list.status.success());
    let list: serde_json::Value = serde_json::from_slice(&list.stdout)?;
    assert_eq!(list["profiles"][0]["provider"], "claude");
    assert_eq!(list["profiles"][0]["alias"], "work");
    let profile_id = list["profiles"][0]["id"]
        .as_str()
        .ok_or("profile id missing")?;
    let credentials = root
        .join("profiles")
        .join("claude")
        .join(profile_id)
        .join("home")
        .join(".credentials.json");
    assert_eq!(
        std::fs::metadata(&credentials)?.permissions().mode() & 0o777,
        0o600
    );
    let initial_credentials = std::fs::read(&credentials)?;

    let verify = configured(&root, &path)
        .env("FAKE_CLAUDE_LOG", &log)
        .args(["auth", "verify", "claude@work"])
        .output()?;
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let failed_reauth = configured(&root, &path)
        .env("FAKE_CLAUDE_LOG", &log)
        .env("FAKE_CLAUDE_CREDENTIAL", "must-not-publish")
        .env("FAKE_CLAUDE_LOGIN_EXIT", "9")
        .args(["auth", "reauth", "claude@work"])
        .output()?;
    assert_eq!(failed_reauth.status.code(), Some(1));
    assert_eq!(std::fs::read(&credentials)?, initial_credentials);

    let reauth = configured(&root, &path)
        .env("FAKE_CLAUDE_LOG", &log)
        .env("FAKE_CLAUDE_CREDENTIAL", "rotated")
        .args(["auth", "reauth", "claude@work"])
        .output()?;
    assert!(
        reauth.status.success(),
        "{}",
        String::from_utf8_lossy(&reauth.stderr)
    );
    assert_ne!(std::fs::read(&credentials)?, initial_credentials);
    assert_eq!(
        std::fs::read_dir(credentials.parent().ok_or("credential parent")?)?.count(),
        1
    );

    let run = configured(&root, &path)
        .env("FAKE_CLAUDE_LOG", &log)
        .env("FAKE_CLAUDE_RUN_EXIT", "23")
        .args(["run", "claude@work", "--", "--print", "synthetic"])
        .output()?;
    assert_eq!(run.status.code(), Some(23));
    assert_eq!(std::fs::read_to_string(&log)?, "--print synthetic\n");

    let rename = configured(&root, &path)
        .args(["auth", "rename", "claude@work", "personal"])
        .output()?;
    assert!(rename.status.success());
    let remove = configured(&root, &path)
        .args(["auth", "remove", "claude@personal", "--yes"])
        .output()?;
    assert!(
        remove.status.success(),
        "{}",
        String::from_utf8_lossy(&remove.stderr)
    );
    assert!(!credentials.exists());

    std::fs::remove_dir_all(sandbox)?;
    Ok(())
}

#[test]
fn failed_claude_login_removes_unpublished_credentials_and_registry_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let (sandbox, path) = fixture()?;
    let root = sandbox.join("state");
    let output = configured(&root, &path)
        .env("FAKE_CLAUDE_LOG", sandbox.join("claude.log"))
        .env("FAKE_CLAUDE_LOGIN_EXIT", "7")
        .args(["auth", "add", "claude", "failed"])
        .output()?;
    assert_eq!(output.status.code(), Some(1));

    let provider_root = root.join("profiles").join("claude");
    assert!(std::fs::read_dir(&provider_root)?.next().is_none());
    let list = configured(&root, &path)
        .args(["--json", "auth", "list"])
        .output()?;
    assert!(list.status.success());
    let registry: serde_json::Value = serde_json::from_slice(&list.stdout)?;
    assert_eq!(registry["profiles"].as_array().map(Vec::len), Some(0));

    std::fs::remove_dir_all(sandbox)?;
    Ok(())
}

#[test]
fn failed_claude_status_never_publishes_the_staged_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let (sandbox, path) = fixture()?;
    let root = sandbox.join("state");
    let output = configured(&root, &path)
        .env("FAKE_CLAUDE_LOG", sandbox.join("claude.log"))
        .env("FAKE_CLAUDE_STATUS_EXIT", "8")
        .args(["auth", "add", "claude", "failed"])
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not authenticated"));

    let provider_root = root.join("profiles").join("claude");
    assert!(std::fs::read_dir(&provider_root)?.next().is_none());
    let list = configured(&root, &path)
        .args(["--json", "auth", "list"])
        .output()?;
    assert!(list.status.success());
    let registry: serde_json::Value = serde_json::from_slice(&list.stdout)?;
    assert_eq!(registry["profiles"].as_array().map(Vec::len), Some(0));

    std::fs::remove_dir_all(sandbox)?;
    Ok(())
}
