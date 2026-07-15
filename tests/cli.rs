use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn calcifer() -> Command {
    Command::new(env!("CARGO_BIN_EXE_calcifer"))
}

#[cfg(unix)]
const AMBIENT_CODEX_AUTH_OVERRIDES: &[(&str, &str)] = &[
    ("OPENAI_API_KEY", "synthetic-ambient-value"),
    ("CODEX_API_KEY", ""),
    ("CODEX_ACCESS_TOKEN", "synthetic-ambient-value"),
    ("CoDeX_AcCeSs_ToKeN", "synthetic-ambient-value"),
    ("OPENAI_ORGANIZATION", "synthetic-ambient-value"),
    ("OPENAI_PROJECT", "synthetic-ambient-value"),
    (
        "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
        "synthetic-ambient-value",
    ),
    ("CODEX_REVOKE_TOKEN_URL_OVERRIDE", "synthetic-ambient-value"),
    (
        "CODEX_APP_SERVER_LOGIN_CLIENT_ID",
        "synthetic-ambient-value",
    ),
    ("CODEX_AUTHAPI_BASE_URL", "synthetic-ambient-value"),
    ("CODEX_APP_SERVER_LOGIN_ISSUER", "synthetic-ambient-value"),
    (
        "CODEX_APP_SERVER_DEV_OPEN_APP_URL",
        "synthetic-ambient-value",
    ),
    (
        "CODEX_APP_SERVER_MANAGED_CONFIG_PATH",
        "synthetic-ambient-value",
    ),
    (
        "CODEX_APP_SERVER_DISABLE_MANAGED_CONFIG",
        "synthetic-ambient-value",
    ),
    (
        "CODEX_APP_SERVER_TEST_USER_CONFIG_FILE",
        "synthetic-ambient-value",
    ),
    ("CODEX_SQLITE_HOME", "synthetic-ambient-value"),
    ("CODEX_REMOTE_AUTH_TOKEN", "synthetic-ambient-value"),
    ("CODEX_CONNECTORS_TOKEN", "synthetic-ambient-value"),
    ("CODEX_CODE_MODE_HOST_PATH", "synthetic-ambient-value"),
    ("CODEX_CLOUD_TASKS_BASE_URL", "synthetic-ambient-value"),
    (
        "CODEX_CLOUD_TASKS_FORCE_INTERNAL",
        "synthetic-ambient-value",
    ),
    ("CODEX_STARTING_DIFF", "synthetic-ambient-value"),
    ("CODEX_EXEC_SERVER_URL", "synthetic-ambient-value"),
    (
        "CODEX_EXEC_SERVER_NOISE_REGISTRY_URL",
        "synthetic-ambient-value",
    ),
    (
        "CODEX_EXEC_SERVER_NOISE_ENVIRONMENT_ID",
        "synthetic-ambient-value",
    ),
    (
        "CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN",
        "synthetic-ambient-value",
    ),
    (
        "CODEX_EXEC_SERVER_NOISE_CHATGPT_ACCOUNT_ID",
        "synthetic-ambient-value",
    ),
    ("CODEX_OSS_BASE_URL", "synthetic-ambient-value"),
    ("CODEX_OSS_PORT", "synthetic-ambient-value"),
    (
        "CODEX_INTERNAL_ORIGINATOR_OVERRIDE",
        "synthetic-ambient-value",
    ),
    ("CODEX_TUI_RECORD_SESSION", "synthetic-ambient-value"),
    ("CODEX_TUI_SESSION_LOG_PATH", "synthetic-ambient-value"),
    ("CODEX_ROLLOUT_TRACE_ROOT", "synthetic-ambient-value"),
    (
        "CODEX_ANALYTICS_EVENTS_CAPTURE_FILE",
        "synthetic-ambient-value",
    ),
    ("CoDeX_TeSt_Future_Auth_Hook", "synthetic-ambient-value"),
    ("CoDeX_FuTuRe_EnDpOiNt_OvErRiDe", "synthetic-ambient-value"),
];

#[cfg(unix)]
fn calcifer_with_ambient_codex_auth_overrides() -> Command {
    let mut command = calcifer();
    command
        .envs(AMBIENT_CODEX_AUTH_OVERRIDES.iter().copied())
        .env("CODEX_HOME", "/synthetic/ambient/codex-home")
        .env("HTTPS_PROXY", "http://127.0.0.1:17842")
        .env("CODEX_CA_CERTIFICATE", "/synthetic/enterprise-ca.pem")
        .env("TERM", "xterm-calcifer-test")
        .env("FAKE_CODEX_EXPECT_PRESERVED_ENV", "1");
    command
}

#[cfg(unix)]
fn install_profile_remove_test_codex(
    sandbox: &std::path::Path,
) -> Result<(std::ffi::OsString, std::path::PathBuf), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let bin = sandbox.join("bin");
    let log = sandbox.join("provider.log");
    std::fs::create_dir_all(&bin)?;
    std::fs::write(&log, b"")?;
    let fake_codex = bin.join("codex");
    std::fs::write(
        &fake_codex,
        r#"#!/bin/sh
set -eu
printf 'args=%s\n' "$*" >> "$FAKE_CODEX_LOG"
if [ "${1:-}" = "-c" ]; then
  [ "${2:-}" = 'cli_auth_credentials_store="file"' ]
  [ "${3:-}" = "-c" ]
  [ "${4:-}" = 'mcp_oauth_credentials_store="file"' ]
  shift 4
fi
case "${1:-}" in
  login)
    umask 077
    printf '{"auth_mode":"chatgpt","tokens":{"account_id":"scope-%s-%s"}}\n' "$PPID" "$$" > "$CODEX_HOME/auth.json"
    ;;
  app-server)
    IFS= read -r initialize
    case "$initialize" in
      *'"method":"initialize"'*'"experimentalApi":false'*) ;;
      *) exit 93 ;;
    esac
    printf '{"id":0,"result":{"userAgent":"calcifer/0.144.4 (test)","platformFamily":"unix","platformOs":"test","codexHome":"%s"}}\n' "$CODEX_HOME"
    while IFS= read -r request; do
      :
    done
    ;;
  *)
    exit 94
    ;;
esac
"#,
    )?;
    std::fs::set_permissions(&fake_codex, std::fs::Permissions::from_mode(0o700))?;

    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let mut path_entries = vec![bin];
    path_entries.extend(std::env::split_paths(&inherited_path));
    Ok((std::env::join_paths(path_entries)?, log))
}

#[cfg(unix)]
fn add_profile_remove_test_profile(
    root: &std::path::Path,
    path: &std::ffi::OsStr,
    log: &std::path::Path,
    alias: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let add = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", path)
        .env("CALCIFER_HOME", root)
        .env("FAKE_CODEX_LOG", log)
        .args(["auth", "add", "codex", alias])
        .output()?;
    if !add.status.success() {
        return Err(std::io::Error::other(format!(
            "failed to add codex@{alias}: {}",
            String::from_utf8_lossy(&add.stderr)
        ))
        .into());
    }
    profile_remove_test_profile_id(root, alias)
}

#[cfg(unix)]
fn profile_remove_test_profile_id(
    root: &std::path::Path,
    alias: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("profiles.json"))?)?;
    registry["profiles"]
        .as_array()
        .and_then(|profiles| {
            profiles
                .iter()
                .find(|profile| profile["provider"] == "codex" && profile["alias"] == alias)
        })
        .and_then(|profile| profile["id"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| std::io::Error::other(format!("missing codex@{alias}")))
        .map_err(Into::into)
}

#[cfg(unix)]
type ProfileRemoveTreeSnapshot = Vec<(std::path::PathBuf, Option<Vec<u8>>)>;

#[cfg(unix)]
fn snapshot_profile_remove_test_tree(
    root: &std::path::Path,
) -> Result<ProfileRemoveTreeSnapshot, Box<dyn std::error::Error>> {
    fn visit(
        root: &std::path::Path,
        path: &std::path::Path,
        entries: &mut Vec<(std::path::PathBuf, Option<Vec<u8>>)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let metadata = std::fs::symlink_metadata(path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            entries.push((relative, None));
            let mut children = std::fs::read_dir(path)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<Result<Vec<_>, _>>()?;
            children.sort();
            for child in children {
                visit(root, &child, entries)?;
            }
        } else if metadata.is_file() {
            entries.push((relative, Some(std::fs::read(path)?)));
        } else {
            return Err(std::io::Error::other("unexpected non-file profile fixture entry").into());
        }
        Ok(())
    }

    let mut entries = Vec::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

#[cfg(unix)]
#[derive(Debug)]
struct ProfileRemovePtyResult {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(unix)]
struct ProfileRemovePtyFixture<'a> {
    sandbox: &'a std::path::Path,
    root: &'a std::path::Path,
    path: &'a std::ffi::OsStr,
    log: &'a std::path::Path,
}

#[cfg(unix)]
fn run_profile_remove_in_pty<F>(
    fixture: &ProfileRemovePtyFixture<'_>,
    alias: &str,
    input: Option<&[u8]>,
    attempt: &str,
    after_prompt: F,
) -> Result<ProfileRemovePtyResult, Box<dyn std::error::Error>>
where
    F: FnOnce() -> Result<(), Box<dyn std::error::Error>>,
{
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let helper = fixture.sandbox.join("profile-remove-pty.py");
    if !helper.exists() {
        std::fs::write(
            &helper,
            r#"import errno
import os
import select
import subprocess
import sys
import termios
import time

stderr_path, stdout_path, status_path, ready_path, continue_path, input_hex, executable, *arguments = sys.argv[1:]
master, slave = os.openpty()
attributes = termios.tcgetattr(slave)
attributes[3] &= ~termios.ECHO
termios.tcsetattr(slave, termios.TCSANOW, attributes)
process = subprocess.Popen(
    [executable, *arguments],
    stdin=slave,
    stdout=subprocess.PIPE,
    stderr=slave,
    close_fds=True,
)
os.close(slave)
stderr = bytearray()
prompt = b"Type 'yes' to continue:"
deadline = time.monotonic() + 10.0
while prompt not in stderr:
    if time.monotonic() >= deadline:
        process.kill()
        raise RuntimeError("timed out waiting for removal prompt")
    readable, _, _ = select.select([master], [], [], 0.05)
    if readable:
        try:
            chunk = os.read(master, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                chunk = b""
            else:
                raise
        if not chunk:
            break
        stderr.extend(chunk)
    if process.poll() is not None and not readable:
        break
if prompt not in stderr:
    raise RuntimeError("removal process exited without a prompt")
with open(ready_path, "xb"):
    pass
deadline = time.monotonic() + 10.0
while not os.path.exists(continue_path):
    if time.monotonic() >= deadline:
        process.kill()
        raise RuntimeError("timed out waiting for test continuation")
    time.sleep(0.01)
if input_hex == "EOF":
    os.write(master, b"\x04")
else:
    os.write(master, bytes.fromhex(input_hex))
while process.poll() is None:
    readable, _, _ = select.select([master], [], [], 0.05)
    if readable:
        try:
            chunk = os.read(master, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                chunk = b""
            else:
                raise
        if chunk:
            stderr.extend(chunk)
process.wait()
while True:
    readable, _, _ = select.select([master], [], [], 0)
    if not readable:
        break
    try:
        chunk = os.read(master, 4096)
    except OSError as error:
        if error.errno == errno.EIO:
            break
        raise
    if not chunk:
        break
    stderr.extend(chunk)
os.close(master)
stdout = process.stdout.read()
with open(stderr_path, "wb") as destination:
    destination.write(stderr)
with open(stdout_path, "wb") as destination:
    destination.write(stdout)
with open(status_path, "w", encoding="ascii") as destination:
    destination.write(str(process.returncode))
"#,
        )?;
    }

    let attempt_root = fixture.sandbox.join(format!("pty-{attempt}"));
    std::fs::create_dir(&attempt_root)?;
    let stderr_path = attempt_root.join("stderr");
    let stdout_path = attempt_root.join("stdout");
    let status_path = attempt_root.join("status");
    let ready_path = attempt_root.join("ready");
    let continue_path = attempt_root.join("continue");
    let input_hex = input.map_or_else(
        || "EOF".to_owned(),
        |bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    );
    let mut helper_process = Command::new("python3")
        .arg(&helper)
        .args([
            stderr_path.as_os_str(),
            stdout_path.as_os_str(),
            status_path.as_os_str(),
            ready_path.as_os_str(),
            continue_path.as_os_str(),
            std::ffi::OsStr::new(&input_hex),
            std::ffi::OsStr::new(env!("CARGO_BIN_EXE_calcifer")),
            std::ffi::OsStr::new("auth"),
            std::ffi::OsStr::new("remove"),
            std::ffi::OsStr::new(&format!("codex@{alias}")),
        ])
        .env("PATH", fixture.path)
        .env("CALCIFER_HOME", fixture.root)
        .env("FAKE_CODEX_LOG", fixture.log)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready_path.exists() {
        if let Some(status) = helper_process.try_wait()? {
            let output = helper_process.wait_with_output()?;
            return Err(std::io::Error::other(format!(
                "PTY helper exited before prompt ({status}): {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        if Instant::now() >= deadline {
            let _ = helper_process.kill();
            let output = helper_process.wait_with_output()?;
            return Err(std::io::Error::other(format!(
                "timed out waiting for PTY helper: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    after_prompt()?;
    std::fs::write(&continue_path, b"continue")?;
    let helper_output = helper_process.wait_with_output()?;
    if !helper_output.status.success() {
        return Err(std::io::Error::other(format!(
            "PTY helper failed: {}{}",
            String::from_utf8_lossy(&helper_output.stdout),
            String::from_utf8_lossy(&helper_output.stderr)
        ))
        .into());
    }
    let status = std::fs::read_to_string(status_path)?.parse()?;
    Ok(ProfileRemovePtyResult {
        status,
        stdout: std::fs::read(stdout_path)?,
        stderr: std::fs::read(stderr_path)?,
    })
}

#[test]
fn help_lists_only_implemented_commands() -> Result<(), Box<dyn std::error::Error>> {
    let output = calcifer().arg("--help").output()?;
    let stdout = String::from_utf8(output.stdout)?;

    assert!(output.status.success());
    assert!(stdout.contains("doctor"));
    for command in ["auth", "run", "resume", "status", "update"] {
        assert!(
            stdout.contains(&format!("  {command}")),
            "{command} must be advertised after implementation"
        );
    }
    for command in ["switch", "use"] {
        assert!(
            !stdout.contains(&format!("  {command}")),
            "{command} must not be advertised before implementation"
        );
    }
    Ok(())
}

#[test]
fn version_identifies_the_pre_release() -> Result<(), Box<dyn std::error::Error>> {
    let output = calcifer().arg("--version").output()?;
    let stdout = String::from_utf8(output.stdout)?;

    assert!(output.status.success());
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
    Ok(())
}

#[test]
fn json_help_and_version_remain_text() -> Result<(), Box<dyn std::error::Error>> {
    let help = calcifer().args(["--json", "--help"]).output()?;
    let version = calcifer().args(["--json", "--version"]).output()?;
    let help_text = String::from_utf8(help.stdout)?;
    let version_text = String::from_utf8(version.stdout)?;

    assert!(help.status.success());
    assert!(version.status.success());
    assert!(help_text.contains("Usage:"));
    assert!(version_text.contains(env!("CARGO_PKG_VERSION")));
    assert!(!help_text.trim_start().starts_with('{'));
    assert!(!version_text.trim_start().starts_with('{'));
    Ok(())
}

#[test]
fn doctor_json_has_a_stable_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let output = calcifer().args(["--json", "doctor"]).output()?;
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["command"], "doctor");
    assert_eq!(document["ok"], true);
    assert_eq!(document["calcifer_version"], env!("CARGO_PKG_VERSION"));
    let checks = document["checks"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("doctor checks must be an array"))?;
    for id in [
        "host",
        "codex_cli",
        "claude_cli",
        "manual_profile_selection",
        "automatic_failover",
    ] {
        assert_eq!(
            checks
                .iter()
                .filter(|check| check["id"].as_str() == Some(id))
                .count(),
            1,
            "expected exactly one {id} check"
        );
    }
    assert!(checks.iter().any(|check| {
        check["id"] == "manual_profile_selection" && check["code"] == "implemented"
    }));
    assert!(checks.iter().any(|check| {
        check["id"] == "automatic_failover" && check["code"] == "not_implemented"
    }));
    Ok(())
}

#[test]
fn unimplemented_commands_are_redacted_and_side_effect_free()
-> Result<(), Box<dyn std::error::Error>> {
    for command in ["switch", "use"] {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sandbox = std::env::temp_dir().join(format!(
            "calcifer-test-{}-{command}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&sandbox)?;
        let secret = "super-secret-value@example.com";
        let output = calcifer()
            .current_dir(&sandbox)
            .env("HOME", sandbox.join("home"))
            .env("USERPROFILE", sandbox.join("userprofile"))
            .env("XDG_CONFIG_HOME", sandbox.join("xdg-config"))
            .env("XDG_DATA_HOME", sandbox.join("xdg-data"))
            .env("CODEX_HOME", sandbox.join("codex"))
            .env("CLAUDE_CONFIG_DIR", sandbox.join("claude"))
            .args(["--json", command, secret])
            .output()?;
        let document: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        let stderr = String::from_utf8(output.stderr)?;

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(document["ok"], false);
        assert_eq!(document["error"]["code"], "usage_error");
        assert!(!stderr.contains(secret));
        assert!(std::fs::read_dir(&sandbox)?.next().is_none());
        std::fs::remove_dir(&sandbox)?;
    }
    Ok(())
}

#[test]
fn empty_status_is_a_successful_stable_json_document() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "calcifer-empty-status-{}-{nonce}",
        std::process::id()
    ));
    let output = calcifer()
        .env("CALCIFER_HOME", &root)
        .args(["--json", "status"])
        .output()?;
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    assert!(output.status.success());
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["command"], "status");
    assert_eq!(document["ok"], true);
    assert_eq!(document["profiles"], serde_json::json!([]));
    assert!(
        !root.exists(),
        "read-only empty status must not create state"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn relative_home_is_rejected_without_creating_secret_storage()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-relative-home-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&sandbox)?;

    let output = calcifer()
        .current_dir(&sandbox)
        .env_remove("CALCIFER_HOME")
        .env_remove("XDG_DATA_HOME")
        .env("HOME", "relative-home")
        .args(["--json", "auth", "list"])
        .output()?;
    let document: serde_json::Value = serde_json::from_slice(&output.stderr)?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(document["error"]["code"], "unsafe_profile_state");
    assert!(std::fs::read_dir(&sandbox)?.next().is_none());

    std::fs::remove_dir(&sandbox)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_normalized_home_is_rejected_before_staging() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-non-normalized-home-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&sandbox)?;
    let non_normalized = sandbox.join("base").join("..").join("state");

    let output = calcifer()
        .env("CALCIFER_HOME", &non_normalized)
        .args(["--json", "auth", "list"])
        .output()?;
    let document: serde_json::Value = serde_json::from_slice(&output.stderr)?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(document["error"]["code"], "unsafe_profile_state");
    assert!(std::fs::read_dir(&sandbox)?.next().is_none());

    std::fs::remove_dir(&sandbox)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn profile_remove_requires_confirmation_and_is_offline_and_lineage_preserving()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-profile-remove-{}-{nonce}",
        std::process::id()
    ));
    let root = sandbox.join("state");
    let provider_root = root.join("profiles/codex");
    let removed_id = "01900000-0000-7000-8000-000000000017";
    let retained_id = "01900000-0000-7000-8000-000000000018";
    let removed = provider_root.join(removed_id);
    let retained = provider_root.join(retained_id);
    let global_codex = sandbox.join("global-codex");
    let offline_bin = sandbox.join("offline-bin");
    for directory in [
        &sandbox,
        &root,
        &root.join("profiles"),
        &provider_root,
        &removed,
        &removed.join("home"),
        &retained,
        &retained.join("home"),
        &global_codex,
        &offline_bin,
    ] {
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let private_files = [
        (removed.join(".calcifer-profile"), removed_id.as_bytes()),
        (removed.join("profile.lock"), b"".as_slice()),
        (removed.join("provider.lock"), b"".as_slice()),
        (
            removed.join(".calcifer-identity"),
            b"synthetic-removed-identity".as_slice(),
        ),
        (
            removed.join("home/auth.json"),
            b"synthetic-removed-auth@example.invalid".as_slice(),
        ),
        (
            removed.join("home/config.toml"),
            b"cli_auth_credentials_store = \"file\"\n".as_slice(),
        ),
        (
            removed.join("home/sessions.jsonl"),
            b"synthetic-removed-session".as_slice(),
        ),
        (retained.join(".calcifer-profile"), retained_id.as_bytes()),
        (retained.join("profile.lock"), b"".as_slice()),
        (retained.join("provider.lock"), b"".as_slice()),
        (
            retained.join(".calcifer-identity"),
            b"synthetic-retained-identity".as_slice(),
        ),
        (
            retained.join("home/auth.json"),
            b"synthetic-retained-auth@example.invalid".as_slice(),
        ),
        (
            retained.join("home/config.toml"),
            b"cli_auth_credentials_store = \"file\"\n".as_slice(),
        ),
        (
            retained.join("home/sessions.jsonl"),
            b"synthetic-retained-session".as_slice(),
        ),
        (
            root.join("identity.key"),
            b"synthetic-installation-key".as_slice(),
        ),
        (
            global_codex.join("auth.json"),
            b"synthetic-global-auth@example.invalid".as_slice(),
        ),
    ];
    for (path, contents) in private_files {
        std::fs::write(&path, contents)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let registry = serde_json::json!({
        "schema_version": 1,
        "profiles": [
            {"id": removed_id, "alias": "work", "provider": "codex", "created_at": 1784073600_i64},
            {"id": retained_id, "alias": "personal", "provider": "codex", "created_at": 1784073601_i64}
        ]
    });
    std::fs::write(
        root.join("profiles.json"),
        serde_json::to_vec_pretty(&registry)?,
    )?;
    std::fs::set_permissions(
        root.join("profiles.json"),
        std::fs::Permissions::from_mode(0o600),
    )?;
    let conversations = serde_json::json!({
        "schema_version": 1,
        "profile_id": removed_id,
        "sentinel": "synthetic-lineage-private-sentinel"
    });
    std::fs::write(
        root.join("conversations.json"),
        serde_json::to_vec_pretty(&conversations)?,
    )?;
    std::fs::set_permissions(
        root.join("conversations.json"),
        std::fs::Permissions::from_mode(0o600),
    )?;

    let registry_before = std::fs::read(root.join("profiles.json"))?;
    let removed_inode = std::fs::metadata(&removed)?.ino();
    let without_confirmation = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["--json", "auth", "remove", "codex@work"])
        .output()?;
    let confirmation_error: serde_json::Value =
        serde_json::from_slice(&without_confirmation.stderr)?;
    assert_eq!(without_confirmation.status.code(), Some(1));
    assert!(without_confirmation.stdout.is_empty());
    assert_eq!(confirmation_error["error"]["code"], "confirmation_required");
    assert_eq!(std::fs::read(root.join("profiles.json"))?, registry_before);
    assert_eq!(std::fs::metadata(&removed)?.ino(), removed_inode);

    let human_without_confirmation = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["auth", "remove", "codex@work"])
        .output()?;
    assert_eq!(human_without_confirmation.status.code(), Some(1));
    assert!(human_without_confirmation.stdout.is_empty());
    assert_eq!(
        String::from_utf8(human_without_confirmation.stderr)?,
        "error: Profile removal requires an explicit TTY confirmation or `--yes`. No local profile state was changed.\n"
    );
    assert_eq!(std::fs::read(root.join("profiles.json"))?, registry_before);
    assert_eq!(std::fs::metadata(&removed)?.ino(), removed_inode);

    let retained_inode = std::fs::metadata(&retained)?.ino();
    let retained_auth = std::fs::read(retained.join("home/auth.json"))?;
    let identity_key_inode = std::fs::metadata(root.join("identity.key"))?.ino();
    let identity_key = std::fs::read(root.join("identity.key"))?;
    let lineage_inode = std::fs::metadata(root.join("conversations.json"))?.ino();
    let lineage = std::fs::read(root.join("conversations.json"))?;
    let global_inode = std::fs::metadata(global_codex.join("auth.json"))?.ino();
    let global_auth = std::fs::read(global_codex.join("auth.json"))?;

    let remove = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .env("CODEX_HOME", &global_codex)
        .args(["--json", "auth", "remove", "codex@work", "--yes"])
        .output()?;
    let rendered = String::from_utf8(remove.stdout.clone())?;
    let document: serde_json::Value = serde_json::from_slice(&remove.stdout)?;
    assert!(
        remove.status.success(),
        "{}",
        String::from_utf8(remove.stderr)?
    );
    assert_eq!(
        document,
        serde_json::json!({
            "schema_version": 1,
            "command": "auth",
            "ok": true,
            "action": "remove",
            "removed": true,
            "profile": {
                "id": removed_id,
                "alias": "work",
                "provider": "codex",
                "created_at": 1784073600_i64
            }
        })
    );
    assert!(!removed.exists());
    assert_eq!(std::fs::metadata(&retained)?.ino(), retained_inode);
    assert_eq!(
        std::fs::read(retained.join("home/auth.json"))?,
        retained_auth
    );
    assert_eq!(
        std::fs::metadata(root.join("identity.key"))?.ino(),
        identity_key_inode
    );
    assert_eq!(std::fs::read(root.join("identity.key"))?, identity_key);
    assert_eq!(
        std::fs::metadata(root.join("conversations.json"))?.ino(),
        lineage_inode
    );
    assert_eq!(std::fs::read(root.join("conversations.json"))?, lineage);
    assert_eq!(
        std::fs::metadata(global_codex.join("auth.json"))?.ino(),
        global_inode
    );
    assert_eq!(std::fs::read(global_codex.join("auth.json"))?, global_auth);
    for private in [
        "synthetic-removed-auth@example.invalid",
        "synthetic-removed-session",
        "synthetic-removed-identity",
        "synthetic-lineage-private-sentinel",
        &root.display().to_string(),
    ] {
        assert!(!rendered.contains(private));
    }

    let human_remove = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["auth", "remove", "codex@personal", "--yes"])
        .output()?;
    assert!(human_remove.status.success());
    assert!(human_remove.stderr.is_empty());
    assert_eq!(
        String::from_utf8(human_remove.stdout)?,
        "Removed codex@personal.\nThe Calcifer-managed credentials and sessions for this local profile are no longer registered.\n"
    );
    assert_eq!(std::fs::read(root.join("identity.key"))?, identity_key);
    assert_eq!(std::fs::read(root.join("conversations.json"))?, lineage);
    assert_eq!(std::fs::read(global_codex.join("auth.json"))?, global_auth);

    std::fs::remove_dir_all(sandbox)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn removed_profile_lineage_never_rebinds_bare_resume_to_a_reused_alias()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-profile-remove-lineage-{}-{nonce}",
        std::process::id()
    ));
    let root = sandbox.join("state");
    let workspace = sandbox.join("workspace");
    std::fs::create_dir_all(workspace.join(".git"))?;
    let (path, provider_log) = install_profile_remove_test_codex(&sandbox)?;
    let removed_id = add_profile_remove_test_profile(&root, &path, &provider_log, "work")?;
    let canonical_workspace = std::fs::canonicalize(&workspace)?;
    let canonical_workspace = canonical_workspace
        .to_str()
        .ok_or_else(|| std::io::Error::other("test workspace path is not UTF-8"))?;
    let conversation_id = "01900000-0000-7000-8000-000000000171";
    let thread_id = "01900000-0000-7000-8000-000000000172";
    let conversation_registry = serde_json::json!({
        "schema_version": 1,
        "revision": 7,
        "conversations": [{
            "conversation_id": conversation_id,
            "provider": "codex",
            "generations": [{
                "generation": 0,
                "profile_id": removed_id,
                "thread_id": thread_id,
                "canonical_cwd": canonical_workspace,
                "codex_version": "0.144.4",
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "bound_at": 1_784_073_600_i64
            }],
            "active_generation": 0,
            "last_safe_lifecycle": "clean"
        }],
        "workspace_heads": [{
            "provider": "codex",
            "canonical_cwd": canonical_workspace,
            "state": "ready",
            "conversation_id": conversation_id,
            "generation": 0
        }],
        "pending_launches": []
    });
    let conversation_path = root.join("conversations.json");
    std::fs::write(
        &conversation_path,
        serde_json::to_vec_pretty(&conversation_registry)?,
    )?;
    std::fs::set_permissions(&conversation_path, std::fs::Permissions::from_mode(0o600))?;
    let immutable_lineage = std::fs::read(&conversation_path)?;

    let remove = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &provider_log)
        .args(["auth", "remove", "codex@work", "--yes"])
        .output()?;
    assert!(
        remove.status.success(),
        "{}",
        String::from_utf8_lossy(&remove.stderr)
    );
    assert_eq!(std::fs::read(&conversation_path)?, immutable_lineage);

    let log_before_removed_resume = std::fs::read(&provider_log)?;
    let removed_resume = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &provider_log)
        .args(["resume"])
        .output()?;
    assert_eq!(removed_resume.status.code(), Some(1));
    assert!(removed_resume.stdout.is_empty());
    let removed_resume_stderr = String::from_utf8(removed_resume.stderr)?;
    assert!(
        removed_resume_stderr.contains("Profile codex profile was not found."),
        "a valid head must resolve its removed immutable profile ID: {removed_resume_stderr}"
    );
    assert_eq!(
        std::fs::read(&provider_log)?,
        log_before_removed_resume,
        "bare resume must reject a removed immutable profile before provider spawn"
    );

    let replacement_id = add_profile_remove_test_profile(&root, &path, &provider_log, "work")?;
    assert_ne!(replacement_id, removed_id);
    assert_eq!(std::fs::read(&conversation_path)?, immutable_lineage);
    let stored_registry: serde_json::Value = serde_json::from_slice(&immutable_lineage)?;
    assert_eq!(
        stored_registry["workspace_heads"][0]["conversation_id"],
        conversation_id
    );
    assert_eq!(stored_registry["workspace_heads"][0]["generation"], 0);
    assert_eq!(
        stored_registry["conversations"][0]["generations"][0]["profile_id"],
        removed_id
    );
    assert_ne!(
        stored_registry["conversations"][0]["generations"][0]["profile_id"],
        replacement_id
    );

    let log_before_reused_alias_resume = std::fs::read(&provider_log)?;
    let reused_alias_resume = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &provider_log)
        .args(["resume"])
        .output()?;
    assert_eq!(reused_alias_resume.status.code(), Some(1));
    assert!(reused_alias_resume.stdout.is_empty());
    assert!(
        String::from_utf8(reused_alias_resume.stderr)?
            .contains("Profile codex profile was not found.")
    );
    assert_eq!(
        std::fs::read(&provider_log)?,
        log_before_reused_alias_resume,
        "alias reuse must not let bare resume spawn the replacement profile"
    );
    assert_eq!(std::fs::read(&conversation_path)?, immutable_lineage);

    std::fs::remove_dir_all(sandbox)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn profile_remove_tty_requires_exact_yes_and_pins_the_prompted_immutable_id()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-profile-remove-pty-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&sandbox)?;
    let root = sandbox.join("state");
    let (path, provider_log) = install_profile_remove_test_codex(&sandbox)?;
    let confirmed_id = add_profile_remove_test_profile(&root, &path, &provider_log, "confirm")?;
    let raced_id = add_profile_remove_test_profile(&root, &path, &provider_log, "work")?;
    let pty_fixture = ProfileRemovePtyFixture {
        sandbox: &sandbox,
        root: &root,
        path: &path,
        log: &provider_log,
    };

    let assert_prompt = |result: &ProfileRemovePtyResult, alias: &str, profile_id: &str| {
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains(&format!(
                "Remove codex@{alias} (local profile {profile_id}, created "
            )),
            "prompt did not identify the selected local reference and immutable ID: {stderr}"
        );
        assert!(
            stderr.contains("deletes only Calcifer-managed local credentials and sessions"),
            "prompt did not bound the local deletion scope: {stderr}"
        );
        assert!(
            stderr.contains("does not revoke provider tokens"),
            "prompt did not disclose provider-token non-revocation: {stderr}"
        );
        assert!(
            stderr.contains("or guarantee secure erasure"),
            "prompt did not disclose the secure-erasure limitation: {stderr}"
        );
        assert!(stderr.contains("Type 'yes' to continue:"));
    };

    let rejected_inputs: [(&str, Option<&[u8]>); 5] = [
        ("short-y", Some(b"y\n")),
        ("uppercase", Some(b"YES\n")),
        ("leading-space", Some(b" yes\n")),
        ("trailing-space", Some(b"yes \n")),
        ("eof", None),
    ];
    for (attempt, input) in rejected_inputs {
        let before = snapshot_profile_remove_test_tree(&root)?;
        let result = run_profile_remove_in_pty(&pty_fixture, "confirm", input, attempt, || Ok(()))?;
        assert_eq!(result.status, 1, "{attempt} unexpectedly confirmed removal");
        assert!(
            result.stdout.is_empty(),
            "{attempt} wrote success to stdout"
        );
        assert_prompt(&result, "confirm", &confirmed_id);
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(
                "Profile removal requires an explicit TTY confirmation or `--yes`. No local profile state was changed."
            )
        );
        assert_eq!(
            snapshot_profile_remove_test_tree(&root)?,
            before,
            "{attempt} changed managed state despite rejected confirmation"
        );
    }

    let provider_log_before_confirmed_remove = std::fs::read(&provider_log)?;
    let confirmed =
        run_profile_remove_in_pty(&pty_fixture, "confirm", Some(b"yes\n"), "exact-yes", || {
            Ok(())
        })?;
    assert_eq!(confirmed.status, 0);
    assert_prompt(&confirmed, "confirm", &confirmed_id);
    assert_eq!(
        String::from_utf8(confirmed.stdout)?,
        "Removed codex@confirm.\nThe Calcifer-managed credentials and sessions for this local profile are no longer registered.\n"
    );
    assert!(
        !String::from_utf8_lossy(&confirmed.stderr).contains("Removed codex@confirm"),
        "success output leaked onto the prompt's stderr stream"
    );
    assert_eq!(
        std::fs::read(&provider_log)?,
        provider_log_before_confirmed_remove,
        "local removal must not invoke the provider"
    );
    assert!(profile_remove_test_profile_id(&root, "confirm").is_err());
    assert_eq!(profile_remove_test_profile_id(&root, "work")?, raced_id);

    let mut replacement_id = None;
    let mut state_after_alias_reuse = None;
    let mut provider_log_after_alias_reuse = None;
    let raced =
        run_profile_remove_in_pty(&pty_fixture, "work", Some(b"yes\n"), "alias-reuse", || {
            let rename = calcifer()
                .env("PATH", &path)
                .env("CALCIFER_HOME", &root)
                .env("FAKE_CODEX_LOG", &provider_log)
                .args(["auth", "rename", "codex@work", "former-work"])
                .output()?;
            if !rename.status.success() {
                return Err(std::io::Error::other(format!(
                    "failed to create alias-reuse race: {}",
                    String::from_utf8_lossy(&rename.stderr)
                ))
                .into());
            }
            replacement_id = Some(add_profile_remove_test_profile(
                &root,
                &path,
                &provider_log,
                "work",
            )?);
            state_after_alias_reuse = Some(snapshot_profile_remove_test_tree(&root)?);
            provider_log_after_alias_reuse = Some(std::fs::read(&provider_log)?);
            Ok(())
        })?;
    let replacement_id = replacement_id
        .ok_or_else(|| std::io::Error::other("alias-reuse hook did not register a profile"))?;
    let state_after_alias_reuse = state_after_alias_reuse
        .ok_or_else(|| std::io::Error::other("alias-reuse hook did not snapshot state"))?;
    assert_ne!(replacement_id, raced_id);
    assert_eq!(raced.status, 1);
    assert!(raced.stdout.is_empty());
    assert_prompt(&raced, "work", &raced_id);
    assert!(String::from_utf8(raced.stderr)?.contains("Profile codex@work was not found."));
    assert_eq!(
        snapshot_profile_remove_test_tree(&root)?,
        state_after_alias_reuse,
        "confirmation pinned to an old ID must not mutate its alias replacement"
    );
    assert_eq!(
        std::fs::read(&provider_log)?,
        provider_log_after_alias_reuse.ok_or_else(|| std::io::Error::other(
            "alias-reuse hook did not snapshot provider log"
        ))?,
        "the stale confirmation must fail before spawning the provider"
    );
    assert_eq!(
        profile_remove_test_profile_id(&root, "former-work")?,
        raced_id
    );
    assert_eq!(
        profile_remove_test_profile_id(&root, "work")?,
        replacement_id
    );

    std::fs::remove_dir_all(sandbox)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn profile_rename_is_offline_atomic_and_preserves_managed_state()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-profile-rename-{}-{nonce}",
        std::process::id()
    ));
    let bin = sandbox.join("bin");
    let offline_bin = sandbox.join("offline-bin");
    let root = sandbox.join("state");
    let provider_log = sandbox.join("provider.log");
    std::fs::create_dir_all(&bin)?;
    std::fs::create_dir(&offline_bin)?;
    let fake_codex = bin.join("codex");
    std::fs::write(
        &fake_codex,
        r#"#!/bin/sh
set -eu
printf 'home=%s args=%s\n' "${CODEX_HOME:-unset}" "$*" >> "$FAKE_CODEX_LOG"
if [ "${1:-}" = "-c" ]; then
  shift 4
fi
case "${1:-}" in
  --version)
    printf 'codex-cli %s\n' "${FAKE_CODEX_VERSION:-0.144.4}"
    ;;
  login)
    umask 077
    printf '{"auth_mode":"chatgpt","tokens":{"account_id":"scope-%s-%s","access_token":"synthetic-private-sentinel@example.invalid"}}\n' "$PPID" "$$" > "$CODEX_HOME/auth.json"
    ;;
  app-server)
    IFS= read -r initialize
    case "$initialize" in
      *'"method":"initialize"'*'"experimentalApi":false'*) ;;
      *) exit 93 ;;
    esac
    printf '{"id":0,"result":{"userAgent":"calcifer/0.144.4 (test)","platformFamily":"unix","platformOs":"test","codexHome":"%s"}}\n' "$CODEX_HOME"
    IFS= read -r initialized || exit 0
    ;;
esac
"#,
    )?;
    std::fs::set_permissions(&fake_codex, std::fs::Permissions::from_mode(0o700))?;
    let path = std::env::join_paths([bin.as_path()])?;

    let add = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &provider_log)
        .args(["auth", "add", "codex", "work"])
        .output()?;
    assert!(add.status.success(), "{}", String::from_utf8(add.stderr)?);
    let add_personal = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &provider_log)
        .args(["auth", "add", "codex", "personal"])
        .output()?;
    assert!(
        add_personal.status.success(),
        "{}",
        String::from_utf8(add_personal.stderr)?
    );

    let registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("profiles.json"))?)?;
    let profile = &registry["profiles"][0];
    let profile_id = profile["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("profile id must be present"))?;
    let created_at = profile["created_at"].clone();
    let profile_dir = root.join("profiles").join("codex").join(profile_id);
    let home = profile_dir.join("home");
    let auth = home.join("auth.json");
    let config = home.join("config.toml");
    let sessions = home.join("sessions.jsonl");
    let identity = profile_dir.join(".calcifer-provider-identity");
    std::fs::write(&sessions, b"synthetic-session-private-sentinel")?;
    std::fs::set_permissions(&sessions, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&identity, b"synthetic-identity-private-sentinel")?;
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600))?;
    let before_inode = std::fs::metadata(&profile_dir)?.ino();
    let before = [
        std::fs::read(&auth)?,
        std::fs::read(&config)?,
        std::fs::read(&sessions)?,
        std::fs::read(&identity)?,
        std::fs::read(profile_dir.join(".calcifer-profile"))?,
    ];
    let provider_log_before = std::fs::read(&provider_log)?;

    let rename = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["--json", "auth", "rename", "codex@work", "client-a"])
        .output()?;
    let rename_document: serde_json::Value = serde_json::from_slice(&rename.stdout)?;
    assert!(
        rename.status.success(),
        "{}",
        String::from_utf8(rename.stderr.clone())?
    );
    assert!(rename.stderr.is_empty());
    assert_eq!(rename_document["schema_version"], 1);
    assert_eq!(rename_document["command"], "auth");
    assert_eq!(rename_document["ok"], true);
    assert_eq!(rename_document["action"], "rename");
    assert_eq!(rename_document["changed"], true);
    assert_eq!(rename_document["from"], "codex@work");
    assert_eq!(rename_document["to"], "codex@client-a");
    assert_eq!(rename_document["profile"]["id"], profile_id);
    assert_eq!(rename_document["profile"]["alias"], "client-a");
    assert_eq!(rename_document["profile"]["provider"], "codex");
    assert_eq!(rename_document["profile"]["created_at"], created_at);

    let rendered = String::from_utf8(rename.stdout)?;
    for private in [
        "synthetic-private-sentinel@example.invalid",
        "synthetic-session-private-sentinel",
        "synthetic-identity-private-sentinel",
        &root.display().to_string(),
    ] {
        assert!(!rendered.contains(private));
    }
    assert_eq!(std::fs::metadata(&profile_dir)?.ino(), before_inode);
    assert_eq!(
        [
            std::fs::read(&auth)?,
            std::fs::read(&config)?,
            std::fs::read(&sessions)?,
            std::fs::read(&identity)?,
            std::fs::read(profile_dir.join(".calcifer-profile"))?,
        ],
        before
    );
    assert_eq!(std::fs::read(&provider_log)?, provider_log_before);

    let stale_handoff = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &provider_log)
        .args(["__internal-codex", profile_id, "codex@work", "run"])
        .output()?;
    let stale_handoff_error = String::from_utf8(stale_handoff.stderr)?;
    assert_eq!(stale_handoff.status.code(), Some(1));
    assert_eq!(
        stale_handoff_error,
        "error: Profile codex@work was not found.\n"
    );
    assert_eq!(std::fs::read(&provider_log)?, provider_log_before);

    let registry_after_rename = std::fs::read(root.join("profiles.json"))?;
    for (arguments, expected_code) in [
        (
            ["codex@client-a", "../private-sentinel"],
            "invalid_profile_alias",
        ),
        (["codex@client-a", "personal"], "profile_already_exists"),
        (["codex@missing", "replacement"], "profile_not_found"),
    ] {
        let failure = calcifer()
            .env("PATH", &offline_bin)
            .env("CALCIFER_HOME", &root)
            .args(["--json", "auth", "rename", arguments[0], arguments[1]])
            .output()?;
        let document: serde_json::Value = serde_json::from_slice(&failure.stderr)?;
        assert_eq!(failure.status.code(), Some(1));
        assert!(failure.stdout.is_empty());
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["command"], "auth");
        assert_eq!(document["ok"], false);
        assert_eq!(document["error"]["code"], expected_code);
        let failure_text = String::from_utf8(failure.stderr)?;
        for private in [
            "synthetic-private-sentinel@example.invalid",
            "synthetic-session-private-sentinel",
            "synthetic-identity-private-sentinel",
            "private-sentinel",
            &root.display().to_string(),
        ] {
            assert!(!failure_text.contains(private));
        }
        assert_eq!(
            std::fs::read(root.join("profiles.json"))?,
            registry_after_rename
        );
    }

    let old = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["--json", "status", "codex@work"])
        .output()?;
    let old_error: serde_json::Value = serde_json::from_slice(&old.stderr)?;
    assert_eq!(old.status.code(), Some(1));
    assert_eq!(old_error["error"]["code"], "profile_not_found");

    let unchanged = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["--json", "auth", "rename", "codex@client-a", "client-a"])
        .output()?;
    let unchanged_document: serde_json::Value = serde_json::from_slice(&unchanged.stdout)?;
    assert!(unchanged.status.success());
    assert_eq!(unchanged_document["changed"], false);
    assert_eq!(unchanged_document["from"], "codex@client-a");
    assert_eq!(unchanged_document["to"], "codex@client-a");

    let human = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["auth", "rename", "codex@client-a", "client-b"])
        .output()?;
    assert!(human.status.success());
    assert_eq!(
        String::from_utf8(human.stdout)?,
        "Renamed codex@client-a to codex@client-b.\n"
    );
    assert!(human.stderr.is_empty());
    assert_eq!(std::fs::read(&provider_log)?, provider_log_before);

    let list = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["--json", "auth", "list"])
        .output()?;
    let list_document: serde_json::Value = serde_json::from_slice(&list.stdout)?;
    assert!(list.status.success());
    assert!(
        list_document["profiles"]
            .as_array()
            .is_some_and(|profiles| {
                profiles
                    .iter()
                    .any(|profile| profile["id"] == profile_id && profile["alias"] == "client-b")
            })
    );

    let status = calcifer()
        .env("PATH", &offline_bin)
        .env("CALCIFER_HOME", &root)
        .args(["--json", "status", "codex@client-b"])
        .output()?;
    let status_document: serde_json::Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status.status.code(), Some(1));
    assert_eq!(status_document["profiles"][0]["profile"], "codex@client-b");
    assert_ne!(
        status_document["profiles"][0]["error"]["code"],
        "profile_not_found"
    );

    for (arguments, version) in [
        (
            vec!["run", "--untracked", "codex@client-b", "--", "--help"],
            None,
        ),
        (vec!["resume", "--untracked", "codex@client-b"], None),
        (
            vec![
                "resume",
                "codex@client-b",
                "01900000-0000-7000-8000-000000000001",
            ],
            Some("0.144.5"),
        ),
    ] {
        let mut command = calcifer();
        command
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &provider_log)
            .args(arguments);
        if let Some(version) = version {
            command.env("FAKE_CODEX_VERSION", version);
        }
        let output = command.output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8(output.stderr)?
        );
    }
    let provider_log_after_launch = String::from_utf8(std::fs::read(&provider_log)?)?;
    assert!(provider_log_after_launch.contains(&format!("home={}", home.display())));
    assert!(provider_log_after_launch.contains(
        "args=-c cli_auth_credentials_store=\"file\" -c mcp_oauth_credentials_store=\"file\" --help"
    ));
    assert!(provider_log_after_launch.contains("resume --last"));
    assert!(provider_log_after_launch.contains("resume 01900000-0000-7000-8000-000000000001"));

    std::fs::remove_dir_all(sandbox)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn managed_codex_profile_supports_status_run_and_exact_resume()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::CommandExt;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-functional-{}-{nonce}",
        std::process::id()
    ));
    let bin = sandbox.join("bin");
    let log = sandbox.join("provider.log");
    let workspace = sandbox.join("workspace");
    let root = workspace.join(".calcifer-state");
    let project_config = workspace.join(".codex").join("config.toml");
    std::fs::create_dir_all(&bin)?;
    std::fs::create_dir_all(workspace.join(".git"))?;
    std::fs::create_dir_all(workspace.join(".codex"))?;
    std::fs::write(&project_config, "debug = {}\n")?;
    let fake_codex = bin.join("codex");
    std::fs::write(
        &fake_codex,
        r#"#!/bin/sh
set -eu
case "$(umask)" in
  0077|077) ;;
  *) exit 98 ;;
esac
if env | grep -Eq '^(OPENAI_API_KEY|OPENAI_ORGANIZATION|OPENAI_PROJECT|CODEX_API_KEY|CODEX_ACCESS_TOKEN|CoDeX_AcCeSs_ToKeN|CODEX_REFRESH_TOKEN_URL_OVERRIDE|CODEX_REVOKE_TOKEN_URL_OVERRIDE|CODEX_APP_SERVER_LOGIN_CLIENT_ID|CODEX_AUTHAPI_BASE_URL|CODEX_APP_SERVER_LOGIN_ISSUER|CODEX_APP_SERVER_DEV_OPEN_APP_URL|CODEX_APP_SERVER_MANAGED_CONFIG_PATH|CODEX_APP_SERVER_DISABLE_MANAGED_CONFIG|CODEX_APP_SERVER_TEST_USER_CONFIG_FILE|CODEX_SQLITE_HOME|CODEX_REMOTE_AUTH_TOKEN|CODEX_CONNECTORS_TOKEN|CODEX_CODE_MODE_HOST_PATH|CODEX_CLOUD_TASKS_BASE_URL|CODEX_CLOUD_TASKS_FORCE_INTERNAL|CODEX_STARTING_DIFF|CODEX_EXEC_SERVER_URL|CODEX_EXEC_SERVER_NOISE_REGISTRY_URL|CODEX_EXEC_SERVER_NOISE_ENVIRONMENT_ID|CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN|CODEX_EXEC_SERVER_NOISE_CHATGPT_ACCOUNT_ID|CODEX_OSS_BASE_URL|CODEX_OSS_PORT|CODEX_INTERNAL_ORIGINATOR_OVERRIDE|CODEX_TUI_RECORD_SESSION|CODEX_TUI_SESSION_LOG_PATH|CODEX_ROLLOUT_TRACE_ROOT|CODEX_ANALYTICS_EVENTS_CAPTURE_FILE|CoDeX_TeSt_Future_Auth_Hook|CoDeX_FuTuRe_EnDpOiNt_OvErRiDe)='; then
  exit 97
fi
if [ "${FAKE_CODEX_EXPECT_PRESERVED_ENV:-}" = "1" ]; then
  [ "${HTTPS_PROXY:-}" = "http://127.0.0.1:17842" ]
  [ "${CODEX_CA_CERTIFICATE:-}" = "/synthetic/enterprise-ca.pem" ]
  [ "${TERM:-}" = "xterm-calcifer-test" ]
fi
if [ "${FAKE_CODEX_REQUIRE_NEUTRAL_CWD:-}" = "1" ]; then
  cursor=$PWD
  while :; do
    if [ -f "$cursor/.codex/config.toml" ] && grep -Eq '^debug[[:space:]]*=' "$cursor/.codex/config.toml"; then
      exit 96
    fi
    if [ -e "$cursor/.git" ]; then
      break
    fi
    parent=$(dirname "$cursor")
    if [ "$parent" = "$cursor" ]; then
      break
    fi
    cursor=$parent
  done
fi
printf 'pwd=%s args=%s\n' "$PWD" "$*" >> "$FAKE_CODEX_LOG"
if [ "${1:-}" = "-c" ]; then
  [ "${2:-}" = 'cli_auth_credentials_store="file"' ]
  [ "${3:-}" = "-c" ]
  [ "${4:-}" = 'mcp_oauth_credentials_store="file"' ]
  shift 4
fi
thread_id=${FAKE_CODEX_THREAD_ID:-01900000-0000-7000-8000-000000000001}
thread_state="$CODEX_HOME/.fake-thread-state"
thread_counter="$CODEX_HOME/.fake-thread-counter"
thread_rollout="$CODEX_HOME/sessions/rollout-synthetic-$thread_id.jsonl"
if [ "${1:-}" != "login" ] && [ "${1:-}" != "app-server" ] && [ "${1:-}" != "--version" ] && [ "${FAKE_CODEX_NO_THREAD:-}" != "1" ]; then
  mkdir -p "$CODEX_HOME/sessions"
  counter=0
  if [ -f "$thread_counter" ]; then
    counter=$(cat "$thread_counter")
  fi
  counter=$((counter + 1))
  printf '%s\n' "$counter" > "$thread_counter"
  printf '%s\n' "$PWD" > "$thread_state"
  if [ ! -f "$thread_rollout" ]; then
    printf '{"timestamp":"2026-07-15T00:00:00Z","type":"session_meta","payload":{"id":"%s","cwd":"%s","cli_version":"0.144.4","source":"cli","parent_thread_id":null,"base_instructions":"prompt sentinel must not persist"}}\n' "$thread_id" "$PWD" > "$thread_rollout"
    printf '%s\n' '{"timestamp":"2026-07-15T00:00:01Z","type":"response_item","payload":{"message":"response sentinel must not persist","tool_args":"tool arguments sentinel must not persist"}}' >> "$thread_rollout"
  fi
  printf '%s\n' '{"timestamp":"2026-07-15T00:00:02Z","type":"event_msg","payload":{"type":"task_started"}}' >> "$thread_rollout"
  case "${1:-}" in
    hold|hold-ignore-int)
      ;;
    *)
      printf '%s\n' '{"timestamp":"2026-07-15T00:00:03Z","type":"event_msg","payload":{"type":"task_complete"}}' >> "$thread_rollout"
      ;;
  esac
fi
case "${1:-}" in
  --version)
    if [ "${FAKE_CODEX_VERSION_HOLD_STDOUT:-}" = "1" ]; then
      (sleep 5) &
    fi
    printf 'codex-cli %s\n' "${FAKE_CODEX_VERSION:-0.144.4}"
    ;;
  login)
    umask 077
    printf '{"auth_mode":"chatgpt","tokens":{"account_id":"scope-%s-%s"}}\n' "$PPID" "$$" > "$CODEX_HOME/auth.json"
    ;;
  app-server)
    if [ "${FAKE_CODEX_APP_SERVER_SHAPE:-}" = "unavailable" ]; then
      exit 90
    fi
    if [ -n "${FAKE_CODEX_APP_SERVER_HOLD_PID:-}" ]; then
      printf '%s\n' "$$" > "$FAKE_CODEX_APP_SERVER_HOLD_PID"
      exec sleep 30
    fi
    IFS= read -r initialize
    case "$initialize" in
      *'"method":"initialize"'*'"experimentalApi":false'*) ;;
      *) exit 93 ;;
    esac
    printf '%s\n' 'app-server-initialize' >> "$FAKE_CODEX_LOG"
    version=${FAKE_CODEX_VERSION:-0.144.4}
    reported_home=${FAKE_CODEX_REPORTED_HOME:-$CODEX_HOME}
    if [ "${FAKE_CODEX_NULL_INITIALIZE:-}" = "1" ] || [ "${FAKE_CODEX_APP_SERVER_SHAPE:-}" = "schema-drift" ]; then
      printf '%s\n' '{"id":0,"result":null}'
    else
      printf '{"id":0,"result":{"userAgent":"calcifer/%s (test)","platformFamily":"unix","platformOs":"test","codexHome":"%s"}}\n' "$version" "$reported_home"
    fi
    if ! IFS= read -r initialized; then
      printf '%s\n' 'app-server-gate-closed' >> "$FAKE_CODEX_LOG"
      exit 0
    fi
    while IFS= read -r request; do
      request_id=$(printf '%s\n' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
      case "$request" in
        *'"method":"thread/list"'*)
          case "$request" in
            *'"sourceKinds":["cli"]'*'"useStateDbOnly":false'*) ;;
            *) exit 92 ;;
          esac
          printf '%s\n' 'app-server-thread-list' >> "$FAKE_CODEX_LOG"
          if [ "${FAKE_CODEX_PAGINATED_INVENTORY:-}" = "1" ]; then
            printf '{"id":%s,"result":{"data":[],"nextCursor":"page-%s"}}\n' "$request_id" "$request_id"
            continue
          fi
          case "$request" in
            *'"archived":true'*)
              printf '{"id":%s,"result":{"data":[],"nextCursor":null}}\n' "$request_id"
              ;;
            *)
              if [ -f "$thread_state" ] && [ -f "$thread_counter" ] && [ -f "$thread_rollout" ]; then
                thread_cwd=$(cat "$thread_state")
                updated_at=$(cat "$thread_counter")
                if [ "${FAKE_CODEX_FIXED_THREAD_TIMESTAMP:-}" = "1" ]; then
                  updated_at=1
                fi
                printf '{"id":%s,"result":{"data":[{"id":"%s","parentThreadId":null,"ephemeral":false,"updatedAt":%s,"recencyAt":%s,"cwd":"%s","cliVersion":"0.144.4","source":"cli","path":"%s","preview":"preview sentinel must not persist","turns":[{"prompt":"prompt sentinel must not persist"}]}],"nextCursor":null}}\n' "$request_id" "$thread_id" "$updated_at" "$updated_at" "$thread_cwd" "$thread_rollout"
              else
                printf '{"id":%s,"result":{"data":[],"nextCursor":null}}\n' "$request_id"
              fi
              ;;
          esac
          ;;
        *'"method":"thread/read"'*)
          case "$request" in
            *'"includeTurns":false'*) ;;
            *) exit 91 ;;
          esac
          printf '%s\n' 'app-server-thread-read' >> "$FAKE_CODEX_LOG"
          requested_thread=$(printf '%s\n' "$request" | sed -n 's/.*"threadId":"\([^"]*\)".*/\1/p')
          if [ "$requested_thread" != "$thread_id" ] || [ ! -f "$thread_state" ] || [ ! -f "$thread_rollout" ]; then
            printf '{"id":%s,"error":{"code":-32001,"message":"thread not found: account-owner@example.invalid"}}\n' "$request_id"
          else
            thread_cwd=$(cat "$thread_state")
            updated_at=$(cat "$thread_counter")
            if [ "${FAKE_CODEX_FIXED_THREAD_TIMESTAMP:-}" = "1" ]; then
              updated_at=1
            fi
            printf '{"id":%s,"result":{"thread":{"id":"%s","parentThreadId":null,"ephemeral":false,"updatedAt":%s,"recencyAt":%s,"cwd":"%s","cliVersion":"0.144.4","source":"cli","path":"%s","preview":"preview sentinel must not persist","turns":[{"response":"response sentinel must not persist"}]}}}\n' "$request_id" "$thread_id" "$updated_at" "$updated_at" "$thread_cwd" "$thread_rollout"
          fi
          ;;
        *'"method":"account/rateLimits/read"'*)
          printf '%s\n' 'app-server-usage-request' >> "$FAKE_CODEX_LOG"
          case "${FAKE_CODEX_USAGE_SHAPE:-complete}" in
            missing-rate-limits)
              printf '%s\n' '{"id":1,"result":{"rateLimitsByLimitId":{"codex":{"primary":{"usedPercent":41}}},"opaqueFuture":"must-not-leak-malformed"}}'
              ;;
            null-rate-limits)
              printf '%s\n' '{"id":1,"result":{"rateLimits":null,"rateLimitsByLimitId":{"codex":{"primary":{"usedPercent":41}}},"opaqueFuture":"must-not-leak-malformed"}}'
              ;;
            complete)
              printf '%s\n' '{"id":1,"result":{"rateLimits":{"limitId":"codex","limitName":"Codex","planType":"pro","rateLimitReachedType":null,"primary":{"usedPercent":41,"windowDurationMins":300,"resetsAt":1800000000},"secondary":{"usedPercent":70,"windowDurationMins":10080,"resetsAt":1800500000},"credits":{"hasCredits":true,"unlimited":false,"balance":"12.50"},"individualLimit":null},"rateLimitsByLimitId":null,"rateLimitResetCredits":{"availableCount":2,"credits":[{"id":"must-not-leak","resetType":"codexRateLimits","status":"available","grantedAt":1700000000,"expiresAt":1900000000,"title":"must-not-leak","description":"must-not-leak"}]}}}'
              ;;
            *)
              exit 95
              ;;
          esac
          ;;
        *)
          exit 94
          ;;
      esac
    done
    printf '%s\n' 'app-server-eof' >> "$FAKE_CODEX_LOG"
    if [ "${FAKE_CODEX_REMOVE_AFTER_APP_SERVER:-}" = "1" ]; then
      rm -f "$0"
    fi
    ;;
  resume)
    if [ -n "${FAKE_CODEX_HOLD_RESUME_PID:-}" ]; then
      printf '%s\n' "$$" > "$FAKE_CODEX_HOLD_RESUME_PID"
      exec sleep 30
    fi
    ;;
  hold)
    printf '%s\n' "$$" > "$FAKE_CODEX_CHILD_PID"
    if [ -n "${FAKE_CODEX_GUARD_PID:-}" ]; then
      printf '%s\n' "$PPID" > "$FAKE_CODEX_GUARD_PID"
    fi
    exec sleep 30
    ;;
  hold-ignore-int)
    printf '%s\n' "$$" > "$FAKE_CODEX_CHILD_PID"
    if [ -n "${FAKE_CODEX_GUARD_PID:-}" ]; then
      printf '%s\n' "$PPID" > "$FAKE_CODEX_GUARD_PID"
    fi
    trap '' INT
    exec sleep 30
    ;;
  background)
    nohup sleep 30 >/dev/null 2>&1 &
    printf '%s\n' "$!" > "$FAKE_CODEX_BACKGROUND_PID"
    ;;
  exit-seven)
    exit 7
    ;;
  trust-project)
    cat >> "$CODEX_HOME/config.toml" <<'EOF'

[projects."/synthetic/repository"]
trust_level = "trusted"
EOF
    ;;
esac
"#,
    )?;
    let mut permissions = std::fs::metadata(&fake_codex)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&fake_codex, permissions)?;
    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let mut path_entries = vec![bin.clone()];
    path_entries.extend(std::env::split_paths(&inherited_path));
    let path = std::env::join_paths(path_entries)?;

    let add = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .args(["auth", "add", "codex", "work"])
        .output()?;
    assert!(add.status.success(), "{}", String::from_utf8(add.stderr)?);

    let unsupported_add = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .env("FAKE_CODEX_VERSION", "0.145.0")
        .args(["auth", "add", "codex", "unsupported"])
        .output()?;
    let unsupported_add_stderr = String::from_utf8(unsupported_add.stderr)?;
    assert_eq!(unsupported_add.status.code(), Some(1));
    assert!(unsupported_add_stderr.contains("not supported"));
    assert!(!root.join("profiles/codex").read_dir()?.any(|entry| {
        entry
            .ok()
            .and_then(|entry| entry.file_name().into_string().ok())
            .is_some_and(|name| name.starts_with(".staging-"))
    }));

    let trust_project = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_NO_THREAD", "1")
        .args(["run", "codex@work", "--", "trust-project"])
        .output()?;
    assert!(
        trust_project.status.success(),
        "{}",
        String::from_utf8(trust_project.stderr)?
    );

    let status = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .args(["--json", "status", "codex@work"])
        .output()?;
    let status_text = String::from_utf8(status.stdout)?;
    let document: serde_json::Value = serde_json::from_str(&status_text)?;
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8(status.stderr)?
    );
    assert_eq!(document["profiles"][0]["availability"], "available");
    assert_eq!(document["profiles"][0]["codex_version"], "0.144.4");
    assert_eq!(
        document["profiles"][0]["adapter_version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        document["profiles"][0]["compatibility"]["status"],
        "compatible"
    );
    assert_eq!(
        document["profiles"][0]["compatibility"]["protocol"],
        "account/rateLimits/read"
    );
    assert_eq!(
        document["profiles"][0]["compatibility"]["supported_codex_versions"],
        serde_json::json!(["0.144.4"])
    );
    assert_eq!(
        document["profiles"][0]["usage"]["rate_limits"]["primary"]["remaining_percent"],
        59
    );
    assert_eq!(
        document["profiles"][0]["usage"]["reset_credits"]["available_count"],
        2
    );
    assert_eq!(
        document["profiles"][0]["usage"]["reset_credits"]["details"][0]["granted_at"],
        1_700_000_000
    );
    assert_eq!(
        document["profiles"][0]["usage"]["reset_credits"]["details"][0]["expires_at"],
        1_900_000_000
    );
    assert_eq!(
        document["profiles"][0]["usage"]["reset_credits"]["details"][0]["status"],
        "available"
    );
    assert!(!status_text.contains("must-not-leak"));

    let usage_reads_before_rejections = std::fs::read_to_string(&log)?
        .matches("app-server-usage-request")
        .count();
    let unsupported = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .env("FAKE_CODEX_VERSION", "0.145.0")
        .args(["--json", "status", "codex@work"])
        .output()?;
    let unsupported_document: serde_json::Value = serde_json::from_slice(&unsupported.stdout)?;
    assert_eq!(unsupported.status.code(), Some(1));
    assert_eq!(
        unsupported_document["profiles"][0]["availability"],
        "unknown"
    );
    assert_eq!(
        unsupported_document["profiles"][0]["codex_version"],
        "0.145.0"
    );
    assert_eq!(
        unsupported_document["profiles"][0]["compatibility"]["status"],
        "incompatible"
    );
    assert_eq!(
        unsupported_document["profiles"][0]["error"]["code"],
        "unsupported"
    );
    assert!(unsupported_document["profiles"][0]["usage"].is_null());

    let malformed_initialize = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .env("FAKE_CODEX_NULL_INITIALIZE", "1")
        .args(["--json", "status", "codex@work"])
        .output()?;
    let malformed_initialize_document: serde_json::Value =
        serde_json::from_slice(&malformed_initialize.stdout)?;
    assert_eq!(malformed_initialize.status.code(), Some(1));
    assert_eq!(
        malformed_initialize_document["profiles"][0]["availability"],
        "unknown"
    );
    assert!(malformed_initialize_document["profiles"][0]["codex_version"].is_null());
    assert_eq!(
        malformed_initialize_document["profiles"][0]["compatibility"]["status"],
        "incompatible"
    );
    assert_eq!(
        malformed_initialize_document["profiles"][0]["error"]["code"],
        "protocol_error"
    );
    assert!(malformed_initialize_document["profiles"][0]["usage"].is_null());

    let unsupported_human = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .env("FAKE_CODEX_VERSION", "0.145.0")
        .args(["status", "codex@work"])
        .output()?;
    let unsupported_human_text = String::from_utf8(unsupported_human.stdout)?;
    assert_eq!(unsupported_human.status.code(), Some(1));
    assert!(unsupported_human_text.contains("[unknown]"));
    assert!(
        unsupported_human_text
            .contains("compatibility incompatible · Codex 0.145.0 · tested 0.144.4")
    );

    let wrong_home = sandbox.join("wrong-codex-home");
    std::fs::create_dir(&wrong_home)?;
    std::fs::set_permissions(&wrong_home, std::fs::Permissions::from_mode(0o700))?;
    let mismatched_home = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .env("FAKE_CODEX_REPORTED_HOME", &wrong_home)
        .args(["--json", "status", "codex@work"])
        .output()?;
    let mismatched_home_text = String::from_utf8(mismatched_home.stdout)?;
    let mismatched_home_document: serde_json::Value = serde_json::from_str(&mismatched_home_text)?;
    assert_eq!(mismatched_home.status.code(), Some(1));
    assert_eq!(
        mismatched_home_document["profiles"][0]["codex_version"],
        "0.144.4"
    );
    assert_eq!(
        mismatched_home_document["profiles"][0]["compatibility"]["status"],
        "incompatible"
    );
    assert_eq!(
        mismatched_home_document["profiles"][0]["error"]["code"],
        "unsupported"
    );
    assert!(!mismatched_home_text.contains(wrong_home.to_string_lossy().as_ref()));
    let rejected_log = std::fs::read_to_string(&log)?;
    assert_eq!(
        rejected_log.matches("app-server-usage-request").count(),
        usage_reads_before_rejections,
        "incompatible App Servers must be rejected before usage is requested"
    );
    assert_eq!(rejected_log.matches("app-server-gate-closed").count(), 6);

    for shape in ["missing-rate-limits", "null-rate-limits"] {
        let malformed_usage = calcifer_with_ambient_codex_auth_overrides()
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
            .env("FAKE_CODEX_USAGE_SHAPE", shape)
            .args(["--json", "status", "codex@work"])
            .output()?;
        let malformed_usage_text = String::from_utf8(malformed_usage.stdout)?;
        let malformed_usage_document: serde_json::Value =
            serde_json::from_str(&malformed_usage_text)?;
        assert_eq!(
            malformed_usage.status.code(),
            Some(1),
            "{shape} must fail closed: {malformed_usage_text}"
        );
        assert_eq!(
            malformed_usage_document["profiles"][0]["availability"],
            "unknown"
        );
        assert_eq!(
            malformed_usage_document["profiles"][0]["compatibility"]["status"],
            "incompatible"
        );
        assert_eq!(
            malformed_usage_document["profiles"][0]["error"]["code"],
            "protocol_error"
        );
        assert!(malformed_usage_document["profiles"][0]["usage"].is_null());
        assert!(!malformed_usage_text.contains("must-not-leak-malformed"));
    }

    let human_status = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .args(["status", "codex@work"])
        .output()?;
    let human_status_text = String::from_utf8(human_status.stdout)?;
    assert!(human_status.status.success());
    assert!(human_status_text.contains("Codex 0.144.4"));
    assert!(human_status_text.contains("tested 0.144.4"));
    std::fs::write(&project_config, "model = \"gpt-5.4\"\n")?;

    let provider_root = root.join("profiles").join("codex");
    let mut profile_directories = std::fs::read_dir(&provider_root)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_dir()))
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'));
    let managed_home = profile_directories
        .next()
        .ok_or_else(|| std::io::Error::other("missing published profile home"))?
        .path()
        .join("home");
    assert!(profile_directories.next().is_none());
    let identity_marker = managed_home
        .parent()
        .ok_or_else(|| std::io::Error::other("missing profile directory"))?
        .join(".calcifer-identity");
    std::fs::remove_file(&identity_marker)?;
    let verify = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REQUIRE_NEUTRAL_CWD", "1")
        .args(["--json", "auth", "verify", "codex@work"])
        .output()?;
    let verify_text = String::from_utf8(verify.stdout)?;
    let verify_document: serde_json::Value = serde_json::from_str(&verify_text)?;
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8(verify.stderr)?
    );
    assert_eq!(verify_document["action"], "verify");
    assert_eq!(verify_document["profiles"][0]["alias"], "work");
    assert!(identity_marker.is_file());
    for private_field in ["fingerprint", "key_id", "account_id", "auth_mode"] {
        assert!(!verify_text.contains(private_field));
    }
    let managed_config = managed_home.join("config.toml");
    let supported_managed_config = std::fs::read(&managed_config)?;
    let sensitive_role = "account-owner@example.invalid";
    let sensitive_role_path = "/private/synthetic/role-config.toml";
    let mut role_config = supported_managed_config.clone();
    role_config.extend_from_slice(
        format!(
            r#"
[agents."{sensitive_role}"]
description = "synthetic role"
config_file = "{sensitive_role_path}"
"#
        )
        .as_bytes(),
    );
    std::fs::write(&managed_config, role_config)?;
    let before_role_config_rejection = std::fs::read_to_string(&log)?;
    let rejected_role_config = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "codex@work", "--", "--help"])
        .output()?;
    let role_config_stderr = String::from_utf8(rejected_role_config.stderr)?;
    assert_eq!(rejected_role_config.status.code(), Some(1));
    assert!(role_config_stderr.contains("supported compatibility policy"));
    assert!(!role_config_stderr.contains("agents"));
    assert!(!role_config_stderr.contains(sensitive_role));
    assert!(!role_config_stderr.contains(sensitive_role_path));
    assert!(!role_config_stderr.contains(&managed_home.display().to_string()));
    assert_eq!(std::fs::read_to_string(&log)?, before_role_config_rejection);
    std::fs::write(&managed_config, &supported_managed_config)?;

    let sensitive_callback_url = "https://account-owner@example.invalid/private/callback";
    let callback_overrides: [(&str, String, &[&str], &str); 2] = [
        (
            "mcp_oauth_callback_url",
            format!("mcp_oauth_callback_url = \"{sensitive_callback_url}\"\n"),
            &["run", "codex@work", "--", "--help"],
            sensitive_callback_url,
        ),
        (
            "mcp_oauth_callback_port",
            "mcp_oauth_callback_port = 48765\n".to_owned(),
            &["resume", "codex@work"],
            "48765",
        ),
    ];
    for (key, callback_override, arguments, sensitive_value) in callback_overrides {
        let mut callback_config = callback_override.into_bytes();
        callback_config.extend_from_slice(&supported_managed_config);
        std::fs::write(&managed_config, callback_config)?;
        let before_callback_rejection = std::fs::read_to_string(&log)?;
        let rejected_callback = calcifer()
            .current_dir(&workspace)
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(arguments)
            .output()?;
        let callback_stderr = String::from_utf8(rejected_callback.stderr)?;
        assert_eq!(rejected_callback.status.code(), Some(1));
        assert!(callback_stderr.contains("supported compatibility policy"));
        assert!(!callback_stderr.contains(key));
        assert!(!callback_stderr.contains(sensitive_value));
        assert!(!callback_stderr.contains(&managed_home.display().to_string()));
        assert_eq!(std::fs::read_to_string(&log)?, before_callback_rejection);
        std::fs::write(&managed_config, &supported_managed_config)?;
    }

    let agents = managed_home.join("agents");
    std::fs::create_dir(&agents)?;
    let before_agents_node_rejection = std::fs::read_to_string(&log)?;
    let rejected_agents_node = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["resume", "codex@work"])
        .output()?;
    let agents_node_stderr = String::from_utf8(rejected_agents_node.stderr)?;
    assert_eq!(rejected_agents_node.status.code(), Some(1));
    assert!(agents_node_stderr.contains("supported compatibility policy"));
    assert!(!agents_node_stderr.contains("agents"));
    assert!(!agents_node_stderr.contains(&managed_home.display().to_string()));
    assert_eq!(std::fs::read_to_string(&log)?, before_agents_node_rejection);
    std::fs::remove_dir(&agents)?;

    let conversation_path = root.join("conversations.json");
    let log_before_untracked_run = std::fs::read_to_string(&log)?;
    let untracked_run = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "--untracked", "codex@work", "--", "exit-seven"])
        .output()?;
    let untracked_run_stderr = String::from_utf8(untracked_run.stderr)?;
    assert_eq!(
        untracked_run.status.code(),
        Some(7),
        "untracked mode must preserve the official provider exit status: {untracked_run_stderr}"
    );
    assert!(
        untracked_run_stderr.contains("conversation capture and bare resume are disabled"),
        "untracked mode did not explain its recovery consequence"
    );
    let log_after_untracked_run = std::fs::read_to_string(&log)?;
    let untracked_run_delta = log_after_untracked_run
        .strip_prefix(&log_before_untracked_run)
        .ok_or_else(|| std::io::Error::other("provider log was replaced"))?;
    assert_eq!(
        untracked_run_delta
            .lines()
            .filter(|line| line.ends_with("exit-seven"))
            .count(),
        1,
        "untracked mode must spawn the official provider exactly once"
    );
    assert!(
        !untracked_run_delta.contains("app-server") && !untracked_run_delta.contains("--version"),
        "untracked mode must not probe or capture provider inventory"
    );
    let untracked_new_head: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        untracked_new_head["workspace_heads"][0]["state"],
        "needs_selection"
    );
    assert_eq!(
        untracked_new_head["conversations"].as_array().map(Vec::len),
        Some(0),
        "untracked mode must not invent a conversation binding"
    );
    assert_eq!(
        untracked_new_head["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "untracked mode must not create a capture baseline"
    );

    let log_before_ambiguous_resume = std::fs::read_to_string(&log)?;
    let untracked_bare_resume = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["resume"])
        .output()?;
    assert_eq!(untracked_bare_resume.status.code(), Some(1));
    assert!(String::from_utf8(untracked_bare_resume.stderr)?.contains("ambiguous"));
    assert_eq!(
        std::fs::read_to_string(&log)?,
        log_before_ambiguous_resume,
        "bare resume after untracked mode must fail before provider spawn"
    );

    let untracked_exact_recovery = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    assert!(
        untracked_exact_recovery.status.success(),
        "{}",
        String::from_utf8(untracked_exact_recovery.stderr)?
    );
    let recovered_untracked_head: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        recovered_untracked_head["workspace_heads"][0]["state"], "ready",
        "explicit exact recovery must restore a tracked head"
    );

    // A different profile lease must not let exact recovery clear the marker
    // while an untracked provider still owns this workspace. The durable
    // ownership record spans provider execution and is removed only after the
    // official child exits; exact recovery is then allowed to restore Ready.
    const PERSONAL_THREAD_ID: &str = "01900000-0000-7000-8000-000000000002";
    let add_personal = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_THREAD_ID", PERSONAL_THREAD_ID)
        .args(["auth", "add", "codex", "personal"])
        .output()?;
    assert!(
        add_personal.status.success(),
        "{}",
        String::from_utf8(add_personal.stderr)?
    );
    let seed_personal_thread = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_THREAD_ID", PERSONAL_THREAD_ID)
        .args(["run", "codex@personal", "--", "--help"])
        .output()?;
    assert!(
        seed_personal_thread.status.success(),
        "{}",
        String::from_utf8(seed_personal_thread.stderr)?
    );

    let active_untracked_pid_file = sandbox.join("active-untracked-provider.pid");
    let mut active_untracked = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_CHILD_PID", &active_untracked_pid_file)
        .args(["run", "--untracked", "codex@work", "--", "hold"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    for _ in 0..500 {
        if active_untracked_pid_file.is_file() || active_untracked.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !active_untracked_pid_file.is_file() {
        let _ = active_untracked.kill();
        let _ = active_untracked.wait();
        return Err(std::io::Error::other("untracked concurrency provider did not start").into());
    }

    let log_before_concurrent_exact = std::fs::read_to_string(&log)?;
    let concurrent_exact = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_THREAD_ID", PERSONAL_THREAD_ID)
        .args(["resume", "codex@personal", PERSONAL_THREAD_ID])
        .output()?;
    assert_eq!(concurrent_exact.status.code(), Some(1));
    assert!(String::from_utf8(concurrent_exact.stderr)?.contains("ambiguous"));
    assert_eq!(
        std::fs::read_to_string(&log)?,
        log_before_concurrent_exact,
        "cross-profile exact recovery reached the provider while untracked ownership was active"
    );
    let active_untracked_registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        active_untracked_registry["workspace_heads"][0]["state"],
        "needs_selection"
    );
    assert_eq!(
        active_untracked_registry["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        active_untracked_registry["pending_launches"][0]["mode"],
        "run_untracked"
    );
    assert!(
        active_untracked_registry["pending_launches"][0]
            .get("codex_version")
            .is_none(),
        "untracked ownership must not claim a version that was never probed"
    );
    assert_eq!(
        active_untracked_registry["pending_launches"][0]["pre_inventory"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "untracked ownership must not contain a capture baseline"
    );

    let active_untracked_pid = std::fs::read_to_string(&active_untracked_pid_file)?;
    let terminated = std::process::Command::new("kill")
        .args(["-TERM", active_untracked_pid.trim()])
        .status()?;
    assert!(terminated.success());
    let _ = active_untracked.wait()?;
    let completed_untracked_registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        completed_untracked_registry["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "untracked ownership must end with the official child"
    );
    assert_eq!(
        completed_untracked_registry["workspace_heads"][0]["state"],
        "needs_selection"
    );

    let exact_after_untracked_exit = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_THREAD_ID", PERSONAL_THREAD_ID)
        .args(["resume", "codex@personal", PERSONAL_THREAD_ID])
        .output()?;
    assert!(
        exact_after_untracked_exit.status.success(),
        "{}",
        String::from_utf8(exact_after_untracked_exit.stderr)?
    );
    let exact_after_untracked_registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        exact_after_untracked_registry["workspace_heads"][0]["state"],
        "ready"
    );

    // The inverse ordering is also unsafe without a head epoch check: an
    // exact provider can adopt Ready first, an untracked launch can invalidate
    // it and finish, and then the older exact provider can exit last. Its
    // lifecycle refresh must not resurrect the pre-untracked head.
    let active_exact_pid_file = sandbox.join("active-exact-provider.pid");
    let mut active_exact = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_THREAD_ID", PERSONAL_THREAD_ID)
        .env("FAKE_CODEX_HOLD_RESUME_PID", &active_exact_pid_file)
        .args(["resume", "codex@personal", PERSONAL_THREAD_ID])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    for _ in 0..500 {
        if active_exact_pid_file.is_file() || active_exact.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !active_exact_pid_file.is_file() {
        let _ = active_exact.kill();
        let _ = active_exact.wait();
        return Err(std::io::Error::other("exact concurrency provider did not start").into());
    }

    let untracked_during_exact = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "--untracked", "codex@work", "--", "--help"])
        .output()?;
    assert!(
        untracked_during_exact.status.success(),
        "{}",
        String::from_utf8(untracked_during_exact.stderr)?
    );
    let invalidated_during_exact: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        invalidated_during_exact["workspace_heads"][0]["state"],
        "needs_selection"
    );
    assert_eq!(
        invalidated_during_exact["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let active_exact_pid = std::fs::read_to_string(&active_exact_pid_file)?;
    let terminated = std::process::Command::new("kill")
        .args(["-TERM", active_exact_pid.trim()])
        .status()?;
    assert!(terminated.success());
    let _ = active_exact.wait()?;
    let after_stale_exact_refresh: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        after_stale_exact_refresh["workspace_heads"][0]["state"], "needs_selection",
        "an exact process adopted before untracked mode must not restore Ready afterward"
    );

    let log_before_stale_exact_bare_resume = std::fs::read_to_string(&log)?;
    let stale_exact_bare_resume = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["resume"])
        .output()?;
    assert_eq!(stale_exact_bare_resume.status.code(), Some(1));
    assert!(String::from_utf8(stale_exact_bare_resume.stderr)?.contains("ambiguous"));
    assert_eq!(
        std::fs::read_to_string(&log)?,
        log_before_stale_exact_bare_resume,
        "bare resume launched after a stale exact refresh"
    );

    let recover_after_stale_exact = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_THREAD_ID", PERSONAL_THREAD_ID)
        .args(["resume", "codex@personal", PERSONAL_THREAD_ID])
        .output()?;
    assert!(
        recover_after_stale_exact.status.success(),
        "{}",
        String::from_utf8(recover_after_stale_exact.stderr)?
    );

    // A final provider spawn failure happens after the untracked marker is
    // durable. The marker must remain ambiguous; spawn failure is not evidence
    // that an uncaptured provider could never have existed.
    {
        let marker_id = uuid::Uuid::new_v4();
        let marker_runtime = std::path::PathBuf::from("/tmp")
            .join(format!("calcifer-{}", rustix::process::getuid().as_raw()));
        let barrier_ready = marker_runtime.join(format!(".test-{marker_id}-final-preflight-ready"));
        let barrier_release =
            marker_runtime.join(format!(".test-{marker_id}-final-preflight-release"));
        let barrier_coordinator = marker_runtime.join(format!(".test-{marker_id}-coordinator.pid"));
        let fake_codex_backup = bin.join("codex-untracked-spawn-failure");
        let log_before_untracked_spawn_failure = std::fs::read_to_string(&log)?;
        let mut untracked_spawn_parent = calcifer()
            .current_dir(&workspace)
            .process_group(0)
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .env("CALCIFER_TEST_MARKER_ID", marker_id.to_string())
            .env("CALCIFER_TEST_FINAL_PREFLIGHT_BARRIER", "1")
            .args(["run", "--untracked", "codex@work", "--", "--help"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        for _ in 0..500 {
            if barrier_ready.is_file() || untracked_spawn_parent.try_wait()?.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !barrier_ready.is_file() {
            let process_group = format!("-{}", untracked_spawn_parent.id());
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &process_group])
                .status();
            let _ = untracked_spawn_parent.wait();
            return Err(
                std::io::Error::other("untracked guardian missed preflight barrier").into(),
            );
        }
        std::fs::rename(&fake_codex, &fake_codex_backup)?;
        let release = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&barrier_release)?;
        release.sync_all()?;
        drop(release);
        let untracked_spawn_failure = untracked_spawn_parent.wait_with_output();
        std::fs::rename(&fake_codex_backup, &fake_codex)?;
        let untracked_spawn_failure = untracked_spawn_failure?;
        if barrier_coordinator.is_file() {
            std::fs::remove_file(&barrier_coordinator)?;
        }
        let untracked_spawn_failure_stderr = String::from_utf8(untracked_spawn_failure.stderr)?;
        assert_eq!(untracked_spawn_failure.status.code(), Some(1));
        assert!(
            untracked_spawn_failure_stderr
                .contains("conversation capture and bare resume are disabled")
        );
        assert_eq!(
            std::fs::read_to_string(&log)?,
            log_before_untracked_spawn_failure,
            "the removed official executable unexpectedly spawned"
        );
        let failed_untracked_head: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
        assert_eq!(
            failed_untracked_head["workspace_heads"][0]["state"], "needs_selection",
            "provider spawn failure must not restore an automatic head"
        );
        assert_eq!(
            failed_untracked_head["pending_launches"]
                .as_array()
                .map(Vec::len),
            Some(0),
            "a definitive spawn failure must release in-flight ownership"
        );

        let failed_untracked_recovery = calcifer()
            .current_dir(&workspace)
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args([
                "resume",
                "codex@work",
                "01900000-0000-7000-8000-000000000001",
            ])
            .output()?;
        assert!(
            failed_untracked_recovery.status.success(),
            "{}",
            String::from_utf8(failed_untracked_recovery.stderr)?
        );
    }

    // An incomplete supported-adapter inventory must never degrade implicitly
    // to an untracked launch. The same command runs only after the user adds
    // the explicit flag, and that path must skip App Server entirely.
    let log_before_incomplete_inventory = std::fs::read_to_string(&log)?;
    let incomplete_inventory = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_PAGINATED_INVENTORY", "1")
        .args(["run", "codex@work", "--", "--help"])
        .output()?;
    assert_eq!(incomplete_inventory.status.code(), Some(1));
    assert!(String::from_utf8(incomplete_inventory.stderr)?.contains("ambiguous"));
    let log_after_incomplete_inventory = std::fs::read_to_string(&log)?;
    let incomplete_inventory_delta = log_after_incomplete_inventory
        .strip_prefix(&log_before_incomplete_inventory)
        .ok_or_else(|| std::io::Error::other("provider log was replaced"))?;
    assert!(
        incomplete_inventory_delta
            .matches("app-server-thread-list")
            .count()
            >= 8,
        "fixture did not reach the bounded pagination limit"
    );
    assert!(
        !incomplete_inventory_delta
            .lines()
            .any(|line| line.ends_with("--help")),
        "normal tracked mode spawned the provider after incomplete inventory"
    );

    let untracked_after_incomplete = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_PAGINATED_INVENTORY", "1")
        .args(["run", "--untracked", "codex@work", "--", "--help"])
        .output()?;
    let untracked_after_incomplete_stderr = String::from_utf8(untracked_after_incomplete.stderr)?;
    assert!(
        untracked_after_incomplete.status.success(),
        "{untracked_after_incomplete_stderr}"
    );
    assert!(
        untracked_after_incomplete_stderr
            .contains("conversation capture and bare resume are disabled")
    );
    let log_after_explicit_untracked = std::fs::read_to_string(&log)?;
    let explicit_untracked_delta = log_after_explicit_untracked
        .strip_prefix(&log_after_incomplete_inventory)
        .ok_or_else(|| std::io::Error::other("provider log was replaced"))?;
    assert_eq!(
        explicit_untracked_delta
            .lines()
            .filter(|line| line.ends_with("--help"))
            .count(),
        1,
        "explicit untracked fallback must spawn the provider exactly once"
    );
    assert!(
        !explicit_untracked_delta.contains("app-server"),
        "explicit untracked fallback unexpectedly inspected inventory"
    );
    let incomplete_untracked_head: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        incomplete_untracked_head["workspace_heads"][0]["state"],
        "needs_selection"
    );

    let incomplete_untracked_recovery = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    assert!(
        incomplete_untracked_recovery.status.success(),
        "{}",
        String::from_utf8(incomplete_untracked_recovery.stderr)?
    );

    let run = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "codex@work", "--", "--help"])
        .output()?;
    assert!(run.status.success(), "{}", String::from_utf8(run.stderr)?);
    let managed_sessions = managed_home.join("sessions");
    let managed_rollout =
        managed_sessions.join("rollout-synthetic-01900000-0000-7000-8000-000000000001.jsonl");
    assert_eq!(
        std::fs::metadata(&managed_sessions)?.permissions().mode() & 0o777,
        0o700,
        "the real provider child must inherit Calcifer's 0077 umask"
    );
    assert_eq!(
        std::fs::metadata(&managed_rollout)?.permissions().mode() & 0o777,
        0o600,
        "the real provider child must create private rollouts"
    );

    let log_before_explicit_resume = std::fs::read_to_string(&log)?;
    let resume = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
            "--",
            "--no-alt-screen",
        ])
        .output()?;
    assert!(
        resume.status.success(),
        "{}",
        String::from_utf8(resume.stderr)?
    );
    let log_after_explicit_resume = std::fs::read_to_string(&log)?;
    assert_eq!(
        log_after_explicit_resume
            .matches("app-server-thread-list")
            .count(),
        log_before_explicit_resume
            .matches("app-server-thread-list")
            .count(),
        "explicit exact adoption must use direct thread/read, not scan old sessions"
    );
    assert!(
        log_after_explicit_resume
            .matches("app-server-thread-read")
            .count()
            >= log_before_explicit_resume
                .matches("app-server-thread-read")
                .count()
                + 2,
        "explicit exact resume validates before launch and refreshes lifecycle after exit"
    );

    let log_before_untracked_resume = std::fs::read_to_string(&log)?;
    let untracked_resume = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["resume", "--untracked", "codex@work"])
        .output()?;
    let untracked_resume_stderr = String::from_utf8(untracked_resume.stderr)?;
    assert!(
        untracked_resume.status.success(),
        "{untracked_resume_stderr}"
    );
    assert!(untracked_resume_stderr.contains("conversation capture and bare resume are disabled"));
    let log_after_untracked_resume = std::fs::read_to_string(&log)?;
    let untracked_resume_delta = log_after_untracked_resume
        .strip_prefix(&log_before_untracked_resume)
        .ok_or_else(|| std::io::Error::other("provider log was replaced"))?;
    assert_eq!(
        untracked_resume_delta
            .lines()
            .filter(|line| line.ends_with("resume --last"))
            .count(),
        1,
        "untracked resume must launch official --last exactly once"
    );
    assert!(
        !untracked_resume_delta.contains("app-server")
            && !untracked_resume_delta.contains("--version")
    );
    let untracked_existing_head: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        untracked_existing_head["workspace_heads"][0]["state"], "needs_selection",
        "untracked resume must invalidate an existing automatic head"
    );

    let untracked_resume_recovery = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    assert!(
        untracked_resume_recovery.status.success(),
        "{}",
        String::from_utf8(untracked_resume_recovery.stderr)?
    );
    let recovered_existing_head: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        recovered_existing_head["workspace_heads"][0]["state"],
        "ready"
    );

    let thread_reads_before_same_second_resume = std::fs::read_to_string(&log)?
        .matches("app-server-thread-read")
        .count();
    let resume_last = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_FIXED_THREAD_TIMESTAMP", "1")
        .args(["resume", "codex@work"])
        .output()?;
    assert!(
        resume_last.status.success(),
        "{}",
        String::from_utf8(resume_last.stderr)?
    );
    assert!(
        std::fs::read_to_string(&log)?
            .matches("app-server-thread-read")
            .count()
            > thread_reads_before_same_second_resume,
        "a same-second rollout length/mtime change must still select the resumed thread"
    );

    let log_before_cold_resume = std::fs::read_to_string(&log)?;
    let cold_resume = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["resume"])
        .output()?;
    assert!(
        cold_resume.status.success(),
        "{}",
        String::from_utf8(cold_resume.stderr.clone())?
    );
    let cold_resume_log = std::fs::read_to_string(&log)?;
    let cold_resume_log = cold_resume_log
        .strip_prefix(&log_before_cold_resume)
        .ok_or_else(|| std::io::Error::other("provider log was replaced during cold resume"))?;
    assert!(cold_resume_log.contains("resume 01900000-0000-7000-8000-000000000001"));
    assert!(!cold_resume_log.contains("resume --last"));
    assert!(!cold_resume_log.contains("prompt sentinel"));
    assert!(String::from_utf8(cold_resume.stderr)?.contains("exact ID; no prompt replay"));

    let conversation_bytes = std::fs::read(&conversation_path)?;
    let conversation_document: serde_json::Value = serde_json::from_slice(&conversation_bytes)?;
    assert_eq!(conversation_document["schema_version"], 1);
    assert_eq!(
        conversation_document["conversations"]
            .as_array()
            .map(Vec::len),
        Some(2),
        "the work binding and cross-profile concurrency fixture must both remain immutable"
    );
    assert_eq!(
        conversation_document["conversations"][0]["generations"][0]["thread_id"],
        "01900000-0000-7000-8000-000000000001"
    );
    assert_eq!(
        conversation_document["conversations"][0]["generations"][0]["canonical_cwd"],
        std::fs::canonicalize(&workspace)?
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(
        conversation_document["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    let conversation_text = String::from_utf8(conversation_bytes.clone())?;
    for forbidden in [
        "prompt sentinel",
        "response sentinel",
        "tool arguments sentinel",
        "preview sentinel",
        "rollout-synthetic",
        "synthetic-test-only",
    ] {
        assert!(
            !conversation_text.contains(forbidden),
            "conversation registry persisted forbidden provider content: {forbidden}"
        );
    }

    for unsupported_version in ["0.145.0", "0.145.0-alpha.11"] {
        for app_server_shape in ["unavailable", "schema-drift"] {
            let log_before = std::fs::read_to_string(&log)?;
            let unsupported_exact = calcifer_with_ambient_codex_auth_overrides()
                .current_dir(&workspace)
                .env("PATH", &path)
                .env("CALCIFER_HOME", &root)
                .env("FAKE_CODEX_LOG", &log)
                .env("FAKE_CODEX_VERSION", unsupported_version)
                .env("FAKE_CODEX_APP_SERVER_SHAPE", app_server_shape)
                .args([
                    "resume",
                    "codex@work",
                    "01900000-0000-7000-8000-000000000001",
                ])
                .output()?;
            assert!(
                unsupported_exact.status.success(),
                "{}",
                String::from_utf8(unsupported_exact.stderr.clone())?
            );
            assert!(
                String::from_utf8(unsupported_exact.stderr)?
                    .contains("continuing with explicit exact resume")
            );
            let log_after = std::fs::read_to_string(&log)?;
            let delta = log_after
                .strip_prefix(&log_before)
                .ok_or_else(|| std::io::Error::other("provider log was replaced"))?;
            assert!(delta.contains("--version"));
            assert!(!delta.contains("app-server"));
            assert!(delta.contains("resume 01900000-0000-7000-8000-000000000001"));
            assert_eq!(
                std::fs::read(&conversation_path)?,
                conversation_bytes,
                "unsupported explicit fallback must not rewrite tracked metadata"
            );
        }
    }

    let log_before_malformed_version = std::fs::read_to_string(&log)?;
    let malformed_version = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_VERSION", "0.145.0-alpha.01")
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    assert_eq!(malformed_version.status.code(), Some(1));
    assert!(String::from_utf8(malformed_version.stderr)?.contains("invalid thread metadata"));
    let malformed_version_log = std::fs::read_to_string(&log)?;
    let malformed_version_delta = malformed_version_log
        .strip_prefix(&log_before_malformed_version)
        .ok_or_else(|| std::io::Error::other("provider log was replaced"))?;
    assert!(malformed_version_delta.contains("--version"));
    assert!(!malformed_version_delta.contains("app-server"));
    assert!(!malformed_version_delta.contains("resume 01900000-0000-7000-8000-000000000001"));
    assert_eq!(std::fs::read(&conversation_path)?, conversation_bytes);

    for app_server_shape in ["unavailable", "schema-drift"] {
        let log_before = std::fs::read_to_string(&log)?;
        let rejected_supported_exact = calcifer()
            .current_dir(&workspace)
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .env("FAKE_CODEX_VERSION", "0.144.4")
            .env("FAKE_CODEX_APP_SERVER_SHAPE", app_server_shape)
            .args([
                "resume",
                "codex@work",
                "01900000-0000-7000-8000-000000000001",
            ])
            .output()?;
        let stderr = String::from_utf8(rejected_supported_exact.stderr)?;
        assert_eq!(rejected_supported_exact.status.code(), Some(1));
        let expected_message = if app_server_shape == "schema-drift" {
            "invalid thread metadata response"
        } else {
            "temporarily unavailable"
        };
        assert!(stderr.contains(expected_message));
        let log_after = std::fs::read_to_string(&log)?;
        let delta = log_after
            .strip_prefix(&log_before)
            .ok_or_else(|| std::io::Error::other("provider log was replaced"))?;
        assert!(delta.contains("--version"));
        assert!(delta.contains("app-server"));
        assert!(!delta.contains("resume 01900000-0000-7000-8000-000000000001"));
        assert_eq!(
            std::fs::read(&conversation_path)?,
            conversation_bytes,
            "supported-version metadata failures must not rewrite tracked metadata"
        );
    }

    let log_before_held_version_stdout = std::fs::read_to_string(&log)?;
    let held_version_started = std::time::Instant::now();
    let held_version_stdout = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_VERSION_HOLD_STDOUT", "1")
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    let held_version_elapsed = held_version_started.elapsed();
    let held_version_stderr = String::from_utf8(held_version_stdout.stderr)?;
    assert_eq!(held_version_stdout.status.code(), Some(1));
    assert!(held_version_stderr.contains("temporarily unavailable"));
    assert!(
        held_version_elapsed < std::time::Duration::from_secs(4),
        "version probe exceeded its wall-clock bound: {held_version_elapsed:?}"
    );
    let log_after_held_version_stdout = std::fs::read_to_string(&log)?;
    let held_version_delta = log_after_held_version_stdout
        .strip_prefix(&log_before_held_version_stdout)
        .ok_or_else(|| std::io::Error::other("provider log was replaced"))?;
    assert!(held_version_delta.contains("--version"));
    assert!(!held_version_delta.contains("app-server"));
    assert!(!held_version_delta.contains("resume 01900000-0000-7000-8000-000000000001"));

    let rollout = managed_rollout;
    std::fs::set_permissions(&managed_sessions, std::fs::Permissions::from_mode(0o755))?;
    std::fs::set_permissions(&rollout, std::fs::Permissions::from_mode(0o644))?;
    let legacy_rollout_resume = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    assert!(
        legacy_rollout_resume.status.success(),
        "{}",
        String::from_utf8(legacy_rollout_resume.stderr)?
    );
    std::fs::set_permissions(&rollout, std::fs::Permissions::from_mode(0o666))?;
    let provider_log_before_unsafe_rollout = std::fs::read_to_string(&log)?;
    let exact_invocations_before = provider_log_before_unsafe_rollout
        .matches(" resume 01900000-0000-7000-8000-000000000001")
        .count();
    let unsafe_rollout_resume = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    let unsafe_rollout_stderr = String::from_utf8(unsafe_rollout_resume.stderr)?;
    assert_eq!(unsafe_rollout_resume.status.code(), Some(1));
    assert!(unsafe_rollout_stderr.contains("session metadata is not supported or is unsafe"));
    assert!(!unsafe_rollout_stderr.contains(&rollout.display().to_string()));
    assert_eq!(
        std::fs::read_to_string(&log)?
            .matches(" resume 01900000-0000-7000-8000-000000000001")
            .count(),
        exact_invocations_before,
        "a supported-version unsafe rollout must fail before the official TUI starts"
    );
    std::fs::set_permissions(&rollout, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&managed_sessions, std::fs::Permissions::from_mode(0o700))?;

    let before_rejected = std::fs::read_to_string(&log)?;
    std::fs::write(&project_config, "debug = {}\n")?;
    let blocked_commands: &[&[&str]] = &[
        &["run", "codex@work"],
        &[
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ],
        &["resume", "codex@work"],
    ];
    for arguments in blocked_commands {
        let rejected = calcifer()
            .current_dir(&workspace)
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(*arguments)
            .output()?;
        let stderr = String::from_utf8(rejected.stderr)?;
        assert_eq!(rejected.status.code(), Some(1));
        assert!(stderr.contains("repository-local Codex configuration"));
        assert!(!stderr.contains("debug"));
        assert!(!stderr.contains(&workspace.display().to_string()));
        assert_eq!(std::fs::read_to_string(&log)?, before_rejected);
    }
    std::fs::write(&project_config, "model = \"gpt-5.4\"\n")?;

    let project_agents = workspace.join(".codex").join("agents");
    let sensitive_project_role = "account-owner@example.invalid";
    let sensitive_project_role_path = project_agents.join(format!("{sensitive_project_role}.toml"));
    std::fs::remove_file(&project_config)?;
    std::fs::create_dir(&project_agents)?;
    std::fs::write(
        &sensitive_project_role_path,
        "model_provider = \"synthetic-external-provider\"\n",
    )?;
    let before_project_agents_rejection = std::fs::read_to_string(&log)?;
    let project_agents_commands: &[&[&str]] = &[
        &["run", "codex@work", "--", "--help"],
        &["resume", "codex@work"],
    ];
    for (index, arguments) in project_agents_commands.iter().enumerate() {
        if index == 1 {
            std::fs::write(&project_config, "model = \"gpt-5.4\"\n")?;
        }
        let rejected = calcifer()
            .current_dir(&workspace)
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(*arguments)
            .output()?;
        let stderr = String::from_utf8(rejected.stderr)?;
        assert_eq!(rejected.status.code(), Some(1));
        assert!(stderr.contains("repository-local Codex configuration"));
        assert!(!stderr.contains("agents"));
        assert!(!stderr.contains(sensitive_project_role));
        assert!(!stderr.contains(&sensitive_project_role_path.display().to_string()));
        assert!(!stderr.contains(&workspace.display().to_string()));
        assert_eq!(
            std::fs::read_to_string(&log)?,
            before_project_agents_rejection
        );
    }
    std::fs::remove_dir_all(&project_agents)?;

    for argument in ["--oss", "--cd=/synthetic/project", "--enable=synthetic"] {
        let rejected = calcifer()
            .current_dir(&workspace)
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(["run", "codex@work", "--", argument])
            .output()?;
        assert_eq!(rejected.status.code(), Some(1));
        assert!(String::from_utf8(rejected.stderr)?.contains("rejected a provider argument"));
        assert_eq!(std::fs::read_to_string(&log)?, before_rejected);
    }

    // Pause the provider guardian after launch authorization and mutate the
    // repository configuration before its final preflight. The guardian must
    // send ABORT, never spawn Codex, and release both lifecycle leases.
    let marker_id = uuid::Uuid::new_v4();
    let marker_runtime = std::path::PathBuf::from("/tmp")
        .join(format!("calcifer-{}", rustix::process::getuid().as_raw()));
    let final_preflight_ready =
        marker_runtime.join(format!(".test-{marker_id}-final-preflight-ready"));
    let final_preflight_release =
        marker_runtime.join(format!(".test-{marker_id}-final-preflight-release"));
    let final_preflight_coordinator =
        marker_runtime.join(format!(".test-{marker_id}-coordinator.pid"));
    let before_final_preflight = std::fs::read_to_string(&log)?;
    let mut preflight_parent = calcifer()
        .process_group(0)
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("CALCIFER_TEST_MARKER_ID", marker_id.to_string())
        .env("CALCIFER_TEST_FINAL_PREFLIGHT_BARRIER", "1")
        .args(["run", "codex@work", "--", "--help"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    for _ in 0..500 {
        if final_preflight_ready.is_file() {
            break;
        }
        if preflight_parent.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !final_preflight_ready.is_file() {
        let process_group = format!("-{}", preflight_parent.id());
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &process_group])
            .status();
        let _ = preflight_parent.wait();
        return Err(std::io::Error::other("guardian did not reach final preflight").into());
    }
    let final_preflight_identity = std::fs::read_to_string(&final_preflight_ready)?;
    let mut final_preflight_identity = final_preflight_identity.split_whitespace();
    let preflight_guardian_pid = final_preflight_identity
        .next()
        .ok_or_else(|| std::io::Error::other("missing final preflight guardian PID"))?
        .to_owned();
    let preflight_run_id = uuid::Uuid::parse_str(
        final_preflight_identity
            .next()
            .ok_or_else(|| std::io::Error::other("missing final preflight run ID"))?,
    )?;
    assert!(final_preflight_identity.next().is_none());
    let preflight_coordinator_pid = std::fs::read_to_string(&final_preflight_coordinator)?
        .trim()
        .to_owned();
    let preflight_socket = marker_runtime.join(format!("{preflight_run_id}.sock"));
    assert!(preflight_socket.exists());

    std::fs::write(&project_config, "debug = {}\n")?;
    let release = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&final_preflight_release)?;
    release.sync_all()?;
    drop(release);
    let rejected_final_preflight = preflight_parent.wait_with_output()?;
    let rejected_final_preflight_stderr = String::from_utf8(rejected_final_preflight.stderr)?;
    assert_eq!(rejected_final_preflight.status.code(), Some(1));
    assert!(rejected_final_preflight_stderr.contains("repository-local Codex configuration"));
    assert!(!rejected_final_preflight_stderr.contains("debug"));
    assert!(!rejected_final_preflight_stderr.contains(&workspace.display().to_string()));
    assert_eq!(std::fs::read_to_string(&log)?, before_final_preflight);
    assert!(!final_preflight_release.exists());
    assert!(!final_preflight_ready.exists());
    assert!(!preflight_socket.exists());
    for exited_pid in [&preflight_guardian_pid, &preflight_coordinator_pid] {
        assert!(
            !std::process::Command::new("kill")
                .args(["-0", exited_pid])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()?
                .success(),
            "lifecycle process {exited_pid} must exit after ABORT"
        );
    }
    std::fs::remove_file(&final_preflight_coordinator)?;

    std::fs::write(&project_config, "model = \"gpt-5.4\"\n")?;
    let retry_after_final_preflight = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "codex@work", "--", "--help"])
        .output()?;
    assert!(
        retry_after_final_preflight.status.success(),
        "{}",
        String::from_utf8(retry_after_final_preflight.stderr)?
    );

    let provider_log = std::fs::read_to_string(&log)?;
    let canonical_workspace = std::fs::canonicalize(&workspace)?;
    assert!(provider_log.contains("resume 01900000-0000-7000-8000-000000000001 --no-alt-screen"));
    assert!(provider_log.contains("resume --last"));
    assert!(provider_log.lines().any(|line| {
        line.starts_with(&format!("pwd={} ", canonical_workspace.display()))
            && line.ends_with("--help")
    }));
    assert!(provider_log.lines().any(|line| line.ends_with(
        "args=-c cli_auth_credentials_store=\"file\" -c mcp_oauth_credentials_store=\"file\" --help"
    )));
    assert!(provider_log.contains("app-server-eof"));
    let neutral_working_directory = std::path::PathBuf::from("/tmp")
        .join(format!("calcifer-{}", rustix::process::getuid().as_raw()))
        .join("neutral");
    let canonical_neutral_working_directory = std::fs::canonicalize(&neutral_working_directory)?;
    assert!(neutral_working_directory.join(".git").is_dir());
    assert_eq!(
        std::fs::metadata(neutral_working_directory.join(".git"))?
            .permissions()
            .mode()
            & 0o077,
        0
    );
    for line in provider_log
        .lines()
        .filter(|line| line.contains(" login") || line.contains(" app-server"))
    {
        assert!(
            line.starts_with(&format!(
                "pwd={} ",
                canonical_neutral_working_directory.display()
            )),
            "login and status must stop repository discovery at the private neutral cwd: {line}"
        );
    }

    // The dedicated supervisor owns the lease. Provider background tools must
    // not inherit it after the official provider process exits.
    let background_pid_file = sandbox.join("provider-background.pid");
    let background = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_BACKGROUND_PID", &background_pid_file)
        .args(["run", "codex@work", "--", "background"])
        .output()?;
    assert!(
        background.status.success(),
        "{}",
        String::from_utf8(background.stderr)?
    );
    let status_after_provider_exit = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["--json", "status", "codex@work"])
        .output()?;
    let background_pid = std::fs::read_to_string(&background_pid_file)?;
    let kill_background = std::process::Command::new("kill")
        .args(["-KILL", background_pid.trim()])
        .status()?;
    assert!(status_after_provider_exit.status.success());
    assert!(kill_background.success());

    // Killing only the user-facing Calcifer process leaves the dedicated
    // supervisor alive, so a live provider still blocks a second writer.
    let child_pid_file = sandbox.join("provider-child.pid");
    let mut parent = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_CHILD_PID", &child_pid_file)
        .args(["run", "codex@work", "--", "hold"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    for _ in 0..200 {
        if child_pid_file.is_file() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !child_pid_file.is_file() {
        let _ = parent.kill();
        let _ = parent.wait();
        return Err(std::io::Error::other("provider child did not start").into());
    }
    parent.kill()?;
    let _ = parent.wait()?;

    let busy = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["--json", "status", "codex@work"])
        .output()?;
    let busy_document: serde_json::Value = serde_json::from_slice(&busy.stdout)?;
    let child_pid = std::fs::read_to_string(&child_pid_file)?;
    let kill_status = std::process::Command::new("kill")
        .args(["-KILL", child_pid.trim()])
        .status()?;

    assert_eq!(busy.status.code(), Some(1));
    assert_eq!(
        busy_document["profiles"][0]["error"]["code"],
        "profile_busy"
    );
    assert!(kill_status.success());

    let mut recovered = false;
    for _ in 0..200 {
        let status = calcifer()
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(["--json", "status", "codex@work"])
            .output()?;
        if status.status.success() {
            recovered = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(recovered, "lease must release after the provider exits");

    // Killing the actual internal coordinator (not only the public wrapper)
    // leaves the provider guardian's B-lock authoritative until Codex exits.
    let coordinator_child_pid_file = sandbox.join("coordinator-provider.pid");
    let marker_runtime = std::path::PathBuf::from("/tmp")
        .join(format!("calcifer-{}", rustix::process::getuid().as_raw()));
    let coordinator_marker_id = uuid::Uuid::new_v4();
    let coordinator_pid_file =
        marker_runtime.join(format!(".test-{coordinator_marker_id}-coordinator.pid"));
    let coordinator_tracked_file =
        marker_runtime.join(format!(".test-{coordinator_marker_id}-provider-tracked"));
    let mut coordinator_parent = calcifer()
        .current_dir(&workspace)
        .process_group(0)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_CHILD_PID", &coordinator_child_pid_file)
        .env("CALCIFER_TEST_MARKER_ID", coordinator_marker_id.to_string())
        .args(["run", "codex@work", "--", "hold"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let coordinator_group = format!("-{}", coordinator_parent.id());
    for _ in 0..500 {
        if coordinator_child_pid_file.is_file()
            && coordinator_pid_file.is_file()
            && coordinator_tracked_file.is_file()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !coordinator_child_pid_file.is_file()
        || !coordinator_pid_file.is_file()
        || !coordinator_tracked_file.is_file()
    {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &coordinator_group])
            .status();
        let _ = coordinator_parent.wait();
        let _ = std::fs::remove_file(&coordinator_pid_file);
        let _ = std::fs::remove_file(&coordinator_tracked_file);
        return Err(std::io::Error::other("coordinator provider did not become tracked").into());
    }
    let coordinator_child_pid = std::fs::read_to_string(&coordinator_child_pid_file)?;
    let coordinator_pid = std::fs::read_to_string(&coordinator_pid_file)?;
    std::fs::remove_file(&coordinator_pid_file)?;
    std::fs::remove_file(&coordinator_tracked_file)?;
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", coordinator_pid.trim()])
            .status()?
            .success()
    );
    let _ = coordinator_parent.wait()?;
    let busy_after_coordinator_kill = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["--json", "status", "codex@work"])
        .output()?;
    let busy_after_coordinator_kill_document: serde_json::Value =
        serde_json::from_slice(&busy_after_coordinator_kill.stdout)?;
    assert_eq!(busy_after_coordinator_kill.status.code(), Some(1));
    assert_eq!(
        busy_after_coordinator_kill_document["profiles"][0]["error"]["code"],
        "profile_busy"
    );
    assert!(
        std::process::Command::new("kill")
            .args(["-0", coordinator_child_pid.trim()])
            .status()?
            .success()
    );
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", coordinator_child_pid.trim()])
            .status()?
            .success()
    );
    let mut recovered_after_coordinator_kill = false;
    for _ in 0..500 {
        let status = calcifer()
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(["--json", "status", "codex@work"])
            .output()?;
        if status.status.success() {
            recovered_after_coordinator_kill = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        recovered_after_coordinator_kill,
        "guardian B-lock must release after the provider exits"
    );
    let coordinator_crash_conversation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        coordinator_crash_conversation["conversations"][0]["last_safe_lifecycle"], "unknown_crash",
        "the surviving guardian must commit an unclean boundary after coordinator failure"
    );
    assert_eq!(
        coordinator_crash_conversation["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let mut clean_rollout = std::fs::OpenOptions::new().append(true).open(&rollout)?;
    clean_rollout.write_all(
        br#"{"timestamp":"2026-07-15T00:00:04Z","type":"event_msg","payload":{"type":"task_complete"}}"#,
    )?;
    clean_rollout.write_all(b"\n")?;
    clean_rollout.sync_all()?;
    let resume_unknown_head_over_clean_rollout = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["resume"])
        .output()?;
    let resume_unknown_stderr = String::from_utf8(resume_unknown_head_over_clean_rollout.stderr)?;
    assert!(
        resume_unknown_head_over_clean_rollout.status.success(),
        "{resume_unknown_stderr}"
    );
    assert!(
        resume_unknown_stderr.contains("did not have a provably clean boundary"),
        "a clean rollout observation must not erase persisted unknown-crash state before launch"
    );
    let completed_resume_conversation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        completed_resume_conversation["conversations"][0]["last_safe_lifecycle"], "clean",
        "only the completed provider lifecycle may clear persisted uncertainty"
    );

    // Killing the provider-side guardian leaves the coordinator lease alive.
    // Once the exact provider PID exits, the coordinator can safely recover.
    let guarded_child_pid_file = sandbox.join("guarded-provider.pid");
    let guardian_pid_file = sandbox.join("provider-guardian.pid");
    let guardian_marker_id = uuid::Uuid::new_v4();
    let guardian_coordinator_file =
        marker_runtime.join(format!(".test-{guardian_marker_id}-coordinator.pid"));
    let guardian_tracked_file =
        marker_runtime.join(format!(".test-{guardian_marker_id}-provider-tracked"));
    let mut guarded_parent = calcifer()
        .current_dir(&workspace)
        .process_group(0)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_CHILD_PID", &guarded_child_pid_file)
        .env("FAKE_CODEX_GUARD_PID", &guardian_pid_file)
        .env("FAKE_CODEX_NO_THREAD", "1")
        .env("CALCIFER_TEST_MARKER_ID", guardian_marker_id.to_string())
        .args(["run", "codex@work", "--", "hold"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let guarded_group = format!("-{}", guarded_parent.id());
    for _ in 0..500 {
        if guarded_child_pid_file.is_file()
            && guardian_pid_file.is_file()
            && guardian_tracked_file.is_file()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !guarded_child_pid_file.is_file()
        || !guardian_pid_file.is_file()
        || !guardian_tracked_file.is_file()
    {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &guarded_group])
            .status();
        let _ = guarded_parent.wait();
        let _ = std::fs::remove_file(&guardian_coordinator_file);
        let _ = std::fs::remove_file(&guardian_tracked_file);
        return Err(std::io::Error::other("guarded provider did not start").into());
    }
    let guarded_child_pid = std::fs::read_to_string(&guarded_child_pid_file)?;
    let guardian_pid = std::fs::read_to_string(&guardian_pid_file)?;
    std::fs::remove_file(&guardian_coordinator_file)?;
    std::fs::remove_file(&guardian_tracked_file)?;
    let kill_guardian = std::process::Command::new("kill")
        .args(["-KILL", guardian_pid.trim()])
        .status()?;
    assert!(kill_guardian.success());

    let busy_after_guardian_kill = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["--json", "status", "codex@work"])
        .output()?;
    let busy_after_guardian_kill_document: serde_json::Value =
        serde_json::from_slice(&busy_after_guardian_kill.stdout)?;
    assert_eq!(busy_after_guardian_kill.status.code(), Some(1));
    assert_eq!(
        busy_after_guardian_kill_document["profiles"][0]["error"]["code"],
        "profile_busy"
    );
    assert!(
        std::process::Command::new("kill")
            .args(["-0", guarded_child_pid.trim()])
            .status()?
            .success(),
        "provider must still be alive immediately after its guardian is killed"
    );
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", guarded_child_pid.trim()])
            .status()?
            .success()
    );
    for _ in 0..500 {
        if guarded_parent.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if guarded_parent.try_wait()?.is_none() {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &guarded_group])
            .status();
        let _ = guarded_parent.wait();
        return Err(std::io::Error::other("coordinator did not recover").into());
    }
    let mut recovered_after_guardian_kill = false;
    for _ in 0..500 {
        let status = calcifer()
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(["--json", "status", "codex@work"])
            .output()?;
        if status.status.success() {
            recovered_after_guardian_kill = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        recovered_after_guardian_kill,
        "lease must recover after the orphaned provider exits"
    );

    let pending_after_guardian_crash: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        pending_after_guardian_crash["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "a dead guardian must leave one durable launch for reconciliation"
    );
    assert_eq!(
        pending_after_guardian_crash["pending_launches"][0]["phase"],
        "provider_started"
    );

    let log_before_pending_untracked = std::fs::read_to_string(&log)?;
    let pending_untracked = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "--untracked", "codex@work", "--", "--help"])
        .output()?;
    assert_eq!(pending_untracked.status.code(), Some(1));
    assert!(String::from_utf8(pending_untracked.stderr)?.contains("ambiguous"));
    assert_eq!(
        std::fs::read_to_string(&log)?,
        log_before_pending_untracked,
        "untracked mode must refuse a prior pending launch before provider spawn"
    );
    let pending_after_untracked_refusal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        pending_after_untracked_refusal["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "untracked refusal must preserve the pending launch for recovery"
    );

    let log_before_crash_resume = std::fs::read_to_string(&log)?;
    let crash_resume = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["resume"])
        .output()?;
    let crash_resume_stderr = String::from_utf8(crash_resume.stderr)?;
    assert_eq!(crash_resume.status.code(), Some(1));
    assert!(crash_resume_stderr.contains("ambiguous"));
    let log_after_crash_resume = std::fs::read_to_string(&log)?;
    let crash_resume_log = log_after_crash_resume
        .strip_prefix(&log_before_crash_resume)
        .ok_or_else(|| std::io::Error::other("provider log was replaced during crash resume"))?;
    assert!(
        !crash_resume_log.contains("resume 01900000-0000-7000-8000-000000000001"),
        "a started launch with no materialized candidate must not start a second provider"
    );
    assert!(!crash_resume_log.contains("resume --last"));
    let recovered_conversation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        recovered_conversation["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        recovered_conversation["workspace_heads"][0]["state"],
        "needs_selection"
    );

    let explicit_crash_recovery = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    assert!(
        explicit_crash_recovery.status.success(),
        "{}",
        String::from_utf8(explicit_crash_recovery.stderr)?
    );

    // A terminal SIGINT reaches the whole foreground process group. The
    // guardian catches it while the provider receives the normal signal, so a
    // provider that ignores SIGINT cannot outlive every lease owner.
    let interrupted_child_pid_file = sandbox.join("interrupted-provider.pid");
    let interrupted_guardian_pid_file = sandbox.join("interrupted-guardian.pid");
    let mut interrupted_parent = calcifer()
        .current_dir(&workspace)
        .process_group(0)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_CHILD_PID", &interrupted_child_pid_file)
        .env("FAKE_CODEX_GUARD_PID", &interrupted_guardian_pid_file)
        .args(["run", "codex@work", "--", "hold-ignore-int"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    for _ in 0..500 {
        if interrupted_child_pid_file.is_file() && interrupted_guardian_pid_file.is_file() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !interrupted_child_pid_file.is_file() || !interrupted_guardian_pid_file.is_file() {
        let _ = interrupted_parent.kill();
        let _ = interrupted_parent.wait();
        return Err(std::io::Error::other("interruptible provider did not start").into());
    }
    let interrupted_child_pid = std::fs::read_to_string(&interrupted_child_pid_file)?;
    let process_group = format!("-{}", interrupted_parent.id());
    assert!(
        std::process::Command::new("kill")
            .args(["-INT", &process_group])
            .status()?
            .success()
    );
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(
        interrupted_parent.try_wait()?.is_none(),
        "the public wrapper must keep the foreground session attached when Codex handles SIGINT"
    );

    let busy_after_interrupt = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["--json", "status", "codex@work"])
        .output()?;
    let busy_after_interrupt_document: serde_json::Value =
        serde_json::from_slice(&busy_after_interrupt.stdout)?;
    assert_eq!(busy_after_interrupt.status.code(), Some(1));
    assert_eq!(
        busy_after_interrupt_document["profiles"][0]["error"]["code"],
        "profile_busy"
    );
    assert!(
        std::process::Command::new("kill")
            .args(["-0", interrupted_child_pid.trim()])
            .status()?
            .success(),
        "provider fixture must still be alive after ignoring SIGINT"
    );
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", interrupted_child_pid.trim()])
            .status()?
            .success()
    );
    for _ in 0..500 {
        if interrupted_parent.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if interrupted_parent.try_wait()?.is_none() {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &process_group])
            .status();
        let _ = interrupted_parent.wait();
        return Err(std::io::Error::other("interrupted wrapper did not exit").into());
    }
    let mut recovered_after_interrupt = false;
    for _ in 0..500 {
        let status = calcifer()
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(["--json", "status", "codex@work"])
            .output()?;
        if status.status.success() {
            recovered_after_interrupt = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        recovered_after_interrupt,
        "guardian lease must release after the interrupted provider exits"
    );

    // The one-shot status app-server inherits only the provider-side lease.
    // If the status parent is killed, another writer remains blocked until the
    // app-server itself exits on EOF or is terminated.
    let app_server_pid_file = sandbox.join("status-app-server.pid");
    let mut status_parent = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_APP_SERVER_HOLD_PID", &app_server_pid_file)
        .args(["--json", "status", "codex@work"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    for _ in 0..500 {
        if app_server_pid_file.is_file() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !app_server_pid_file.is_file() {
        let _ = status_parent.kill();
        let _ = status_parent.wait();
        return Err(std::io::Error::other("status app-server did not start").into());
    }
    status_parent.kill()?;
    let _ = status_parent.wait()?;
    let busy_after_status_kill = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["--json", "status", "codex@work"])
        .output()?;
    let busy_after_status_kill_document: serde_json::Value =
        serde_json::from_slice(&busy_after_status_kill.stdout)?;
    assert_eq!(busy_after_status_kill.status.code(), Some(1));
    assert_eq!(
        busy_after_status_kill_document["profiles"][0]["error"]["code"],
        "profile_busy"
    );
    let app_server_pid = std::fs::read_to_string(&app_server_pid_file)?;
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", app_server_pid.trim()])
            .status()?
            .success()
    );
    let mut recovered_after_status_kill = false;
    for _ in 0..500 {
        let status = calcifer()
            .env("PATH", &path)
            .env("CALCIFER_HOME", &root)
            .env("FAKE_CODEX_LOG", &log)
            .args(["--json", "status", "codex@work"])
            .output()?;
        if status.status.success() {
            recovered_after_status_kill = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        recovered_after_status_kill,
        "provider-side status lease must recover after app-server exit"
    );

    // Explicit exact recovery must retain an existing unclean lifecycle even
    // when a pending launch hides the workspace head and thread/read observes
    // a later clean record. Removing the fixture executable after thread/read
    // makes the provider spawn fail, proving pre-launch adoption alone cannot
    // clear the durable uncertainty.
    let mut explicit_failure_registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        explicit_failure_registry["conversations"][0]["last_safe_lifecycle"],
        "unknown_crash"
    );
    clean_rollout.write_all(
        br#"{"timestamp":"2026-07-15T00:00:05Z","type":"event_msg","payload":{"type":"task_complete"}}"#,
    )?;
    clean_rollout.write_all(b"\n")?;
    clean_rollout.sync_all()?;
    let exact_profile_id =
        explicit_failure_registry["conversations"][0]["generations"][0]["profile_id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("missing exact-resume profile ID"))?
            .to_owned();
    let exact_canonical_cwd = std::fs::canonicalize(&workspace)?
        .to_str()
        .ok_or_else(|| std::io::Error::other("non-UTF-8 exact-resume workspace"))?
        .to_owned();
    explicit_failure_registry["revision"] = serde_json::json!(
        explicit_failure_registry["revision"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("missing registry revision"))?
            + 1
    );
    explicit_failure_registry["workspace_heads"][0]["state"] = serde_json::json!("needs_selection");
    explicit_failure_registry["pending_launches"] = serde_json::json!([{
        "launch_id": uuid::Uuid::new_v4().to_string(),
        "profile_id": exact_profile_id,
        "canonical_cwd": exact_canonical_cwd,
        "mode": "resume_last",
        "codex_version": "0.144.4",
        "adapter_version": env!("CARGO_PKG_VERSION"),
        "pre_inventory": [],
        "phase": "capture_failed",
        "started_at": 1
    }]);
    std::fs::write(
        &conversation_path,
        serde_json::to_vec_pretty(&explicit_failure_registry)?,
    )?;

    let explicit_spawn_failure = calcifer()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_REMOVE_AFTER_APP_SERVER", "1")
        .args([
            "resume",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ])
        .output()?;
    let explicit_spawn_failure_stderr = String::from_utf8(explicit_spawn_failure.stderr)?;
    assert_eq!(explicit_spawn_failure.status.code(), Some(1));
    assert!(
        explicit_spawn_failure_stderr.contains("did not have a provably clean boundary"),
        "explicit exact recovery erased persisted uncertainty before spawn"
    );
    let explicit_failure_after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&conversation_path)?)?;
    assert_eq!(
        explicit_failure_after["conversations"][0]["last_safe_lifecycle"], "unknown_crash",
        "a failed provider spawn must not clear persisted uncertainty"
    );
    assert_eq!(
        explicit_failure_after["pending_launches"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "explicit recovery must resolve the matching stale pending launch"
    );
    assert_eq!(
        explicit_failure_after["workspace_heads"][0]["state"], "ready",
        "explicit selection must restore the exact immutable workspace head"
    );
    assert!(
        !fake_codex.exists(),
        "the provider spawn fixture did not fail"
    );

    std::fs::remove_dir_all(sandbox)?;
    Ok(())
}

#[test]
fn human_usage_errors_do_not_echo_unknown_values() -> Result<(), Box<dyn std::error::Error>> {
    let secret = "super-secret-value@example.com";
    let output = calcifer().args(["doctor", secret]).output()?;
    let stderr = String::from_utf8(output.stderr)?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!stderr.contains(secret));
    assert!(stderr.contains("invalid command-line arguments"));
    Ok(())
}

#[test]
fn untracked_resume_rejects_bare_and_exact_forms_before_spawning_helpers()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-untracked-usage-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&sandbox)?;
    let state = sandbox.join("state-must-not-exist");
    for arguments in [
        vec!["resume", "--untracked"],
        vec![
            "resume",
            "--untracked",
            "codex@work",
            "01900000-0000-7000-8000-000000000001",
        ],
    ] {
        let output = calcifer()
            .current_dir(&sandbox)
            .env("CALCIFER_HOME", &state)
            .args(arguments)
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8(output.stderr)?.contains("invalid command-line arguments"));
        assert!(
            !state.exists(),
            "invalid untracked form reached a stateful helper"
        );
    }
    std::fs::remove_dir(&sandbox)?;
    Ok(())
}

#[test]
fn provider_json_flag_does_not_change_calcifer_error_rendering()
-> Result<(), Box<dyn std::error::Error>> {
    let output = calcifer()
        .args(["run", "invalid", "--", "--json"])
        .output()?;
    let stderr = String::from_utf8(output.stderr)?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(stderr.starts_with("error: invalid command-line arguments"));
    assert!(!stderr.trim_start().starts_with('{'));
    Ok(())
}
