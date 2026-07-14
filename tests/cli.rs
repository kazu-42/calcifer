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

#[test]
fn help_lists_only_implemented_commands() -> Result<(), Box<dyn std::error::Error>> {
    let output = calcifer().arg("--help").output()?;
    let stdout = String::from_utf8(output.stdout)?;

    assert!(output.status.success());
    assert!(stdout.contains("doctor"));
    for command in ["auth", "run", "resume", "status"] {
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
fn managed_codex_profile_supports_status_run_and_exact_resume()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let sandbox = std::env::temp_dir().join(format!(
        "calcifer-functional-{}-{nonce}",
        std::process::id()
    ));
    let bin = sandbox.join("bin");
    let root = sandbox.join("state");
    let log = sandbox.join("provider.log");
    std::fs::create_dir_all(&bin)?;
    let fake_codex = bin.join("codex");
    std::fs::write(
        &fake_codex,
        r#"#!/bin/sh
set -eu
if env | grep -Eq '^(OPENAI_API_KEY|OPENAI_ORGANIZATION|OPENAI_PROJECT|CODEX_API_KEY|CODEX_ACCESS_TOKEN|CoDeX_AcCeSs_ToKeN|CODEX_REFRESH_TOKEN_URL_OVERRIDE|CODEX_REVOKE_TOKEN_URL_OVERRIDE|CODEX_APP_SERVER_LOGIN_CLIENT_ID|CODEX_AUTHAPI_BASE_URL|CODEX_APP_SERVER_LOGIN_ISSUER|CODEX_APP_SERVER_DEV_OPEN_APP_URL|CODEX_APP_SERVER_MANAGED_CONFIG_PATH|CODEX_APP_SERVER_DISABLE_MANAGED_CONFIG|CODEX_APP_SERVER_TEST_USER_CONFIG_FILE|CODEX_SQLITE_HOME|CODEX_REMOTE_AUTH_TOKEN|CODEX_CONNECTORS_TOKEN|CODEX_CODE_MODE_HOST_PATH|CODEX_CLOUD_TASKS_BASE_URL|CODEX_CLOUD_TASKS_FORCE_INTERNAL|CODEX_STARTING_DIFF|CODEX_EXEC_SERVER_URL|CODEX_EXEC_SERVER_NOISE_REGISTRY_URL|CODEX_EXEC_SERVER_NOISE_ENVIRONMENT_ID|CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN|CODEX_EXEC_SERVER_NOISE_CHATGPT_ACCOUNT_ID|CODEX_OSS_BASE_URL|CODEX_OSS_PORT|CODEX_INTERNAL_ORIGINATOR_OVERRIDE|CODEX_TUI_RECORD_SESSION|CODEX_TUI_SESSION_LOG_PATH|CODEX_ROLLOUT_TRACE_ROOT|CODEX_ANALYTICS_EVENTS_CAPTURE_FILE|CoDeX_TeSt_Future_Auth_Hook|CoDeX_FuTuRe_EnDpOiNt_OvErRiDe)='; then
  exit 97
fi
if [ "${FAKE_CODEX_EXPECT_PRESERVED_ENV:-}" = "1" ]; then
  [ "${HTTPS_PROXY:-}" = "http://127.0.0.1:17842" ]
  [ "${CODEX_CA_CERTIFICATE:-}" = "/synthetic/enterprise-ca.pem" ]
  [ "${TERM:-}" = "xterm-calcifer-test" ]
fi
printf 'pwd=%s args=%s\n' "$PWD" "$*" >> "$FAKE_CODEX_LOG"
if [ "${1:-}" = "-c" ]; then
  [ "${2:-}" = 'cli_auth_credentials_store="file"' ]
  shift 2
fi
case "${1:-}" in
  login)
    umask 077
    printf '%s\n' '{"fake":"synthetic-test-only"}' > "$CODEX_HOME/auth.json"
    ;;
  app-server)
    if [ -n "${FAKE_CODEX_APP_SERVER_HOLD_PID:-}" ]; then
      printf '%s\n' "$$" > "$FAKE_CODEX_APP_SERVER_HOLD_PID"
      exec sleep 30
    fi
    IFS= read -r initialize
    printf '%s\n' '{"id":0,"result":{"userAgent":"fake","platformFamily":"unix","platformOs":"test","codexHome":"redacted"}}'
    IFS= read -r initialized
    IFS= read -r request
    printf '%s\n' '{"id":1,"result":{"rateLimits":{"limitId":"codex","limitName":"Codex","planType":"pro","rateLimitReachedType":null,"primary":{"usedPercent":41,"windowDurationMins":300,"resetsAt":1800000000},"secondary":{"usedPercent":70,"windowDurationMins":10080,"resetsAt":1800500000},"credits":{"hasCredits":true,"unlimited":false,"balance":"12.50"},"individualLimit":null},"rateLimitsByLimitId":null,"rateLimitResetCredits":{"availableCount":2,"credits":[{"id":"must-not-leak","resetType":"codexRateLimits","status":"available","grantedAt":1700000000,"expiresAt":1900000000,"title":"must-not-leak","description":"must-not-leak"}]}}}'
    while IFS= read -r trailing; do :; done
    printf '%s\n' 'app-server-eof' >> "$FAKE_CODEX_LOG"
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
        .args(["auth", "add", "codex", "work"])
        .output()?;
    assert!(add.status.success(), "{}", String::from_utf8(add.stderr)?);

    let status = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
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

    let resume = calcifer_with_ambient_codex_auth_overrides()
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

    let run = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "codex@work", "--", "--help"])
        .output()?;
    assert!(run.status.success(), "{}", String::from_utf8(run.stderr)?);

    let resume_last = calcifer_with_ambient_codex_auth_overrides()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["resume", "codex@work"])
        .output()?;
    assert!(
        resume_last.status.success(),
        "{}",
        String::from_utf8(resume_last.stderr)?
    );

    let before_rejected = std::fs::read_to_string(&log)?;
    let rejected = calcifer()
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "codex@work", "--", "--oss"])
        .output()?;
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8(rejected.stderr)?.contains("rejected a provider argument"));
    assert_eq!(std::fs::read_to_string(&log)?, before_rejected);

    let provider_log = std::fs::read_to_string(&log)?;
    assert!(provider_log.contains("resume 01900000-0000-7000-8000-000000000001 --no-alt-screen"));
    assert!(provider_log.contains("resume --last"));
    assert!(
        provider_log
            .lines()
            .any(|line| line.ends_with("args=-c cli_auth_credentials_store=\"file\" --help"))
    );
    assert!(provider_log.contains("app-server-eof"));
    for line in provider_log
        .lines()
        .filter(|line| line.contains(" login") || line.contains(" app-server"))
    {
        assert!(
            line.contains("/profiles/codex/") && line.contains("/home args="),
            "login and status must use the managed neutral cwd: {line}"
        );
    }

    // The dedicated supervisor owns the lease. Provider background tools must
    // not inherit it after the official provider process exits.
    let background_pid_file = sandbox.join("provider-background.pid");
    let background = calcifer()
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
        .process_group(0)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_CHILD_PID", &guarded_child_pid_file)
        .env("FAKE_CODEX_GUARD_PID", &guardian_pid_file)
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

    // A terminal SIGINT reaches the whole foreground process group. The
    // guardian catches it while the provider receives the normal signal, so a
    // provider that ignores SIGINT cannot outlive every lease owner.
    let interrupted_child_pid_file = sandbox.join("interrupted-provider.pid");
    let interrupted_guardian_pid_file = sandbox.join("interrupted-guardian.pid");
    let mut interrupted_parent = calcifer()
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
