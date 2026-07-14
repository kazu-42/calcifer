use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn calcifer() -> Command {
    Command::new(env!("CARGO_BIN_EXE_calcifer"))
}

#[test]
fn help_lists_only_implemented_commands() -> Result<(), Box<dyn std::error::Error>> {
    let output = calcifer().arg("--help").output()?;
    let stdout = String::from_utf8(output.stdout)?;

    assert!(output.status.success());
    assert!(stdout.contains("doctor"));
    for command in ["auth", "run", "switch", "use"] {
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
    for id in ["host", "codex_cli", "claude_cli", "account_switching"] {
        assert_eq!(
            checks
                .iter()
                .filter(|check| check["id"].as_str() == Some(id))
                .count(),
            1,
            "expected exactly one {id} check"
        );
    }
    assert!(
        checks.iter().any(|check| {
            check["id"] == "account_switching" && check["code"] == "not_implemented"
        })
    );
    Ok(())
}

#[test]
fn unimplemented_commands_are_redacted_and_side_effect_free()
-> Result<(), Box<dyn std::error::Error>> {
    for command in ["auth", "run", "switch", "use"] {
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
