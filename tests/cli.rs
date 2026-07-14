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
thread_id=01900000-0000-7000-8000-000000000001
thread_state="$CODEX_HOME/.fake-thread-state"
thread_counter="$CODEX_HOME/.fake-thread-counter"
thread_rollout="$CODEX_HOME/sessions/rollout-synthetic-$thread_id.jsonl"
if [ "${1:-}" != "login" ] && [ "${1:-}" != "app-server" ] && [ "${FAKE_CODEX_NO_THREAD:-}" != "1" ]; then
  umask 077
  mkdir -p "$CODEX_HOME/sessions"
  counter=0
  if [ -f "$thread_counter" ]; then
    counter=$(cat "$thread_counter")
  fi
  counter=$((counter + 1))
  printf '%s\n' "$counter" > "$thread_counter"
  printf '%s\n' "$PWD" > "$thread_state"
  printf '{"timestamp":"2026-07-15T00:00:00Z","type":"session_meta","payload":{"id":"%s","cwd":"%s","cli_version":"0.144.4","source":"cli","parent_thread_id":null,"base_instructions":"prompt sentinel must not persist"}}\n' "$thread_id" "$PWD" > "$thread_rollout"
  printf '%s\n' '{"timestamp":"2026-07-15T00:00:01Z","type":"response_item","payload":{"message":"response sentinel must not persist","tool_args":"tool arguments sentinel must not persist"}}' >> "$thread_rollout"
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
    case "$initialize" in
      *'"method":"initialize"'*'"experimentalApi":false'*) ;;
      *) exit 93 ;;
    esac
    printf '%s\n' 'app-server-initialize' >> "$FAKE_CODEX_LOG"
    version=${FAKE_CODEX_VERSION:-0.144.4}
    reported_home=${FAKE_CODEX_REPORTED_HOME:-$CODEX_HOME}
    if [ "${FAKE_CODEX_NULL_INITIALIZE:-}" = "1" ]; then
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
          case "$request" in
            *'"archived":true'*)
              printf '{"id":%s,"result":{"data":[],"nextCursor":null}}\n' "$request_id"
              ;;
            *)
              if [ -f "$thread_state" ] && [ -f "$thread_counter" ] && [ -f "$thread_rollout" ]; then
                thread_cwd=$(cat "$thread_state")
                updated_at=$(cat "$thread_counter")
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
    assert_eq!(rejected_log.matches("app-server-gate-closed").count(), 4);

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

    let run = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .args(["run", "codex@work", "--", "--help"])
        .output()?;
    assert!(run.status.success(), "{}", String::from_utf8(run.stderr)?);

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

    let resume_last = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
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

    let conversation_path = root.join("conversations.json");
    let conversation_bytes = std::fs::read(&conversation_path)?;
    let conversation_document: serde_json::Value = serde_json::from_slice(&conversation_bytes)?;
    assert_eq!(conversation_document["schema_version"], 1);
    assert_eq!(
        conversation_document["conversations"]
            .as_array()
            .map(Vec::len),
        Some(1)
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

    let unsupported_exact = calcifer_with_ambient_codex_auth_overrides()
        .current_dir(&workspace)
        .env("PATH", &path)
        .env("CALCIFER_HOME", &root)
        .env("FAKE_CODEX_LOG", &log)
        .env("FAKE_CODEX_VERSION", "0.145.0")
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
    assert_eq!(
        std::fs::read(&conversation_path)?,
        conversation_bytes,
        "unsupported explicit fallback must not rewrite tracked metadata"
    );

    let rollout = managed_home
        .join("sessions")
        .join("rollout-synthetic-01900000-0000-7000-8000-000000000001.jsonl");
    std::fs::set_permissions(&rollout, std::fs::Permissions::from_mode(0o644))?;
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
