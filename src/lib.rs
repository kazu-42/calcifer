mod cli;
mod commands;
mod conversations;
mod error;
mod executable;
mod output;
mod profiles;
mod project_config;
mod provider_identity;
mod providers;

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::process::{ExitCode, ExitStatus};

use clap::{CommandFactory, Parser, error::ErrorKind};

use crate::cli::{AuthCommand, Cli, Commands, ProviderArgument, UpdateCommand};
use crate::error::AppError;
use crate::output::ErrorReport;

const HUMAN_USAGE_ERROR: &str =
    "error: invalid command-line arguments\n\nRun 'calcifer --help' for usage.";
const HUMAN_INTERNAL_ERROR: &str = "error: Calcifer could not render or write diagnostic output.";
const JSON_INTERNAL_ERROR: &str = r#"{"schema_version":1,"command":null,"ok":false,"error":{"code":"internal_error","message":"Calcifer could not render or write output"}}"#;

/// Runs the non-shipping supervisor process fixture used by Calcifer's
/// cross-process fault-injection tests.
#[cfg(feature = "internal-supervisor-fixture")]
#[doc(hidden)]
pub fn run_internal_supervisor_fixture() -> ExitCode {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        providers::codex::run_internal_fixture(std::env::args_os())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        ExitCode::FAILURE
    }
}

/// Returns whether this feature-gated process was entered as the sealed Codex
/// TUI launcher. This is not a CLI command and is unavailable in normal builds.
#[cfg(feature = "internal-supervisor-fixture")]
#[doc(hidden)]
pub fn internal_tui_launcher_requested() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        providers::codex::internal_tui_launcher_requested()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Runs the sealed, feature-gated Codex TUI launcher entrypoint.
#[cfg(feature = "internal-supervisor-fixture")]
#[doc(hidden)]
pub fn run_internal_tui_launcher() -> ExitCode {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        providers::codex::run_internal_tui_launcher()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        ExitCode::FAILURE
    }
}

/// Returns whether this default-off process was exec'd as the sealed
/// production-shaped Codex guardian.
#[cfg(feature = "internal-supervisor-fixture")]
#[doc(hidden)]
pub fn internal_production_supervisor_role_requested() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        providers::codex::internal_production_role_requested()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Runs the sealed production-shaped guardian role. This is an internal exec
/// boundary, not a public CLI command.
#[cfg(feature = "internal-supervisor-fixture")]
#[doc(hidden)]
pub fn run_internal_production_supervisor_role() -> ExitCode {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        providers::codex::run_internal_production_role()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        ExitCode::FAILURE
    }
}

/// Runs Calcifer with an explicit argument iterator.
///
/// This boundary keeps process-global argument handling out of command logic and
/// makes the CLI contract testable without touching credentials or provider state.
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    #[cfg(feature = "internal-supervisor-fixture")]
    if internal_production_supervisor_role_requested() {
        return run_internal_production_supervisor_role();
    }

    #[cfg(feature = "internal-supervisor-fixture")]
    if internal_tui_launcher_requested() {
        return run_internal_tui_launcher();
    }

    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let json_requested = args
        .iter()
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json");

    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let exit_code = error.exit_code();
            if error.print().is_err() {
                return ExitCode::FAILURE;
            }
            return exit_code_from_i32(exit_code);
        }
        Err(error) if json_requested => {
            let report = ErrorReport::usage();
            let rendered = report
                .to_json()
                .unwrap_or_else(|_| JSON_INTERNAL_ERROR.to_owned());
            if write_stderr(&rendered).is_err() {
                return ExitCode::FAILURE;
            }
            return exit_code_from_i32(error.exit_code());
        }
        Err(error) => {
            let exit_code = error.exit_code();
            if write_stderr(HUMAN_USAGE_ERROR).is_err() {
                return ExitCode::FAILURE;
            }
            return exit_code_from_i32(exit_code);
        }
    };

    match cli.command {
        Commands::Doctor => {
            let report = commands::doctor::inspect();
            let rendered = if cli.json {
                report.to_json()
            } else {
                Ok(report.to_human())
            };
            let rendered = match rendered {
                Ok(rendered) => rendered,
                Err(_) => {
                    let message = if cli.json {
                        JSON_INTERNAL_ERROR
                    } else {
                        HUMAN_INTERNAL_ERROR
                    };
                    let _ = write_stderr(message);
                    return ExitCode::FAILURE;
                }
            };
            if write_stdout(&rendered).is_err() {
                let message = if cli.json {
                    JSON_INTERNAL_ERROR
                } else {
                    HUMAN_INTERNAL_ERROR
                };
                let _ = write_stderr(message);
                return ExitCode::FAILURE;
            }
            ExitCode::from(report.exit_code())
        }
        Commands::Auth { command } => match command {
            AuthCommand::Add {
                provider: ProviderArgument::Codex,
                alias,
            } => {
                if cli.json {
                    return render_app_error("auth", &AppError::InteractiveJsonUnsupported, true);
                }
                match commands::auth::add_codex(&alias) {
                    Ok(report) => render_auth_report(&report, false),
                    Err(error) => render_app_error("auth", &error, false),
                }
            }
            AuthCommand::Verify { profile } => match profile.provider {
                ProviderArgument::Codex => match commands::auth::verify_codex(&profile.alias) {
                    Ok(report) => render_auth_report(&report, cli.json),
                    Err(error) => render_app_error("auth", &error, cli.json),
                },
            },
            AuthCommand::Rename { profile, new_alias } => match profile.provider {
                ProviderArgument::Codex => {
                    match commands::auth::rename_codex(&profile.alias, &new_alias) {
                        Ok(report) => render_rename_report(&report, cli.json),
                        Err(error) => render_app_error("auth", &error, cli.json),
                    }
                }
            },
            AuthCommand::Remove { profile, yes } => match profile.provider {
                ProviderArgument::Codex => {
                    if !yes
                        && (cli.json || !io::stdin().is_terminal() || !io::stderr().is_terminal())
                    {
                        return render_app_error("auth", &AppError::ConfirmationRequired, cli.json);
                    }
                    let registry = match profiles::Registry::discover().map_err(AppError::from) {
                        Ok(registry) => registry,
                        Err(error) => return render_app_error("auth", &error, cli.json),
                    };
                    let confirmed_profile_id = if !yes {
                        let preview =
                            match commands::auth::preview_remove_codex(&registry, &profile.alias) {
                                Ok(preview) => preview,
                                Err(error) => return render_app_error("auth", &error, false),
                            };
                        let prompt = format!(
                            "Remove {} (local profile {}, created {})?\nThis deletes only Calcifer-managed local credentials and sessions; it does not revoke provider tokens or guarantee secure erasure.\nType 'yes' to continue:",
                            preview.reference(),
                            preview.id,
                            preview.created_at
                        );
                        if write_stderr(&prompt).is_err() {
                            return ExitCode::FAILURE;
                        }
                        let mut confirmation = String::new();
                        if io::stdin().read_line(&mut confirmation).is_err()
                            || !is_explicit_confirmation(&confirmation)
                        {
                            return render_app_error(
                                "auth",
                                &AppError::ConfirmationRequired,
                                false,
                            );
                        }
                        Some(preview.id)
                    } else {
                        None
                    };
                    match commands::auth::remove_codex(
                        &registry,
                        &profile.alias,
                        confirmed_profile_id.as_deref(),
                    ) {
                        Ok(report) => render_remove_report(&report, cli.json),
                        Err(error) => render_app_error("auth", &error, cli.json),
                    }
                }
            },
            AuthCommand::List => match commands::auth::list() {
                Ok(report) => render_auth_report(&report, cli.json),
                Err(error) => render_app_error("auth", &error, cli.json),
            },
        },
        Commands::Run {
            untracked,
            profile,
            provider_args,
        } => {
            if cli.json {
                return render_app_error("run", &AppError::InteractiveJsonUnsupported, true);
            }
            match profile.provider {
                ProviderArgument::Codex => {
                    match commands::process::run_codex(&profile.alias, untracked, &provider_args) {
                        Ok(status) => exit_code_from_status(status),
                        Err(error) => render_app_error("run", &error, false),
                    }
                }
            }
        }
        Commands::Resume {
            untracked,
            profile,
            session_id,
            provider_args,
        } => {
            if cli.json {
                return render_app_error("resume", &AppError::InteractiveJsonUnsupported, true);
            }
            let result = match profile {
                Some(profile) => match profile.provider {
                    ProviderArgument::Codex => commands::process::resume_codex(
                        &profile.alias,
                        session_id.as_deref(),
                        untracked,
                        &provider_args,
                    ),
                },
                None if !untracked && session_id.is_none() => {
                    commands::process::resume_workspace_codex(&provider_args)
                }
                None => Err(AppError::ProviderArgumentRejected),
            };
            match result {
                Ok(status) => exit_code_from_status(status),
                Err(error) => render_app_error("resume", &error, false),
            }
        }
        Commands::Status { profile } => match commands::status::StatusReport::inspect(
            profile.as_ref().map(|profile| profile.alias.as_str()),
        ) {
            Ok(report) => render_status_report(&report, cli.json),
            Err(error) => render_app_error("status", &error, cli.json),
        },
        Commands::Update {
            command: UpdateCommand::Check { channel },
        } => match commands::update::check(channel) {
            Ok(report) => render_update_report(&report, cli.json),
            Err(error) => render_app_error("update", &error.into(), cli.json),
        },
        Commands::InternalCodex {
            profile_id,
            expected_profile,
            mode,
            session_id,
            provider_args,
        } => {
            if cli.json {
                return render_app_error(
                    "__internal-codex",
                    &AppError::InteractiveJsonUnsupported,
                    true,
                );
            }
            match expected_profile.provider {
                ProviderArgument::Codex => {
                    let notice = match mode {
                        cli::InternalProcessMode::Run => format!(
                            "Calcifer: launching codex@{} (explicit profile).",
                            expected_profile.alias
                        ),
                        cli::InternalProcessMode::RunUntracked => format!(
                            "Calcifer: launching codex@{} in explicit untracked mode.",
                            expected_profile.alias
                        ),
                        cli::InternalProcessMode::ResumeLast => format!(
                            "Calcifer: resuming latest session in codex@{} (same profile; no prompt replay).",
                            expected_profile.alias
                        ),
                        cli::InternalProcessMode::ResumeLastUntracked => format!(
                            "Calcifer: resuming the latest session in codex@{} in explicit untracked mode.",
                            expected_profile.alias
                        ),
                        cli::InternalProcessMode::ResumeExact => format!(
                            "Calcifer: resuming requested thread in codex@{} (same profile; no prompt replay).",
                            expected_profile.alias
                        ),
                        cli::InternalProcessMode::ResumeHead => format!(
                            "Calcifer: resuming this workspace's tracked thread in codex@{} (same profile; exact ID; no prompt replay).",
                            expected_profile.alias
                        ),
                    };
                    match commands::process::supervise_codex(
                        profile_id.as_str(),
                        &expected_profile.alias,
                        mode,
                        session_id.as_deref(),
                        &provider_args,
                        || write_stderr(&notice),
                    ) {
                        Ok(status) => exit_code_from_status(status),
                        Err(error) => render_app_error("__internal-codex", &error, false),
                    }
                }
            }
        }
        Commands::InternalCodexProvider {
            profile_id,
            run_id,
            mode,
            session_id,
            provider_args,
        } => {
            if cli.json {
                return render_app_error(
                    "__internal-codex-provider",
                    &AppError::InteractiveJsonUnsupported,
                    true,
                );
            }
            match commands::process::guard_codex(
                profile_id.as_str(),
                &run_id,
                mode,
                session_id.as_deref(),
                &provider_args,
            ) {
                Ok(status) => exit_code_from_status(status),
                Err(error) => render_app_error("__internal-codex-provider", &error, false),
            }
        }
    }
}

fn render_auth_report(report: &commands::auth::AuthReport, json: bool) -> ExitCode {
    let rendered = if json {
        report.to_json()
    } else {
        Ok(report.to_human())
    };
    match rendered {
        Ok(rendered) if write_stdout(&rendered).is_ok() => ExitCode::SUCCESS,
        _ => {
            let _ = write_stderr(if json {
                JSON_INTERNAL_ERROR
            } else {
                HUMAN_INTERNAL_ERROR
            });
            ExitCode::FAILURE
        }
    }
}

fn render_rename_report(report: &commands::auth::RenameReport, json: bool) -> ExitCode {
    let rendered = if json {
        report.to_json()
    } else {
        Ok(report.to_human())
    };
    match rendered {
        Ok(rendered) if write_stdout(&rendered).is_ok() => ExitCode::SUCCESS,
        _ => {
            let _ = write_stderr(if json {
                JSON_INTERNAL_ERROR
            } else {
                HUMAN_INTERNAL_ERROR
            });
            ExitCode::FAILURE
        }
    }
}

fn render_remove_report(report: &commands::auth::RemoveReport, json: bool) -> ExitCode {
    let rendered = if json {
        report.to_json()
    } else {
        Ok(report.to_human())
    };
    match rendered {
        Ok(rendered) if write_stdout(&rendered).is_ok() => ExitCode::SUCCESS,
        _ => {
            let _ = write_stderr(if json {
                JSON_INTERNAL_ERROR
            } else {
                HUMAN_INTERNAL_ERROR
            });
            ExitCode::FAILURE
        }
    }
}

fn render_status_report(report: &commands::status::StatusReport, json: bool) -> ExitCode {
    let rendered = if json {
        report.to_json()
    } else {
        Ok(report.to_human())
    };
    match rendered {
        Ok(rendered) if write_stdout(&rendered).is_ok() => ExitCode::from(report.exit_code()),
        _ => {
            let _ = write_stderr(if json {
                JSON_INTERNAL_ERROR
            } else {
                HUMAN_INTERNAL_ERROR
            });
            ExitCode::FAILURE
        }
    }
}

fn render_update_report(report: &commands::update::UpdateReport, json: bool) -> ExitCode {
    let rendered = if json {
        report.to_json()
    } else {
        Ok(report.to_human())
    };
    match rendered {
        Ok(rendered) if write_stdout(&rendered).is_ok() => ExitCode::SUCCESS,
        _ => {
            let _ = write_stderr(if json {
                JSON_INTERNAL_ERROR
            } else {
                HUMAN_INTERNAL_ERROR
            });
            ExitCode::FAILURE
        }
    }
}

fn render_app_error(command: &str, error: &AppError, json: bool) -> ExitCode {
    let rendered = if json {
        ErrorReport::command(command, error.code(), error.safe_message())
            .to_json()
            .unwrap_or_else(|_| JSON_INTERNAL_ERROR.to_owned())
    } else {
        format!("error: {}", error.safe_message())
    };
    if write_stderr(&rendered).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::FAILURE
}

fn exit_code_from_status(status: ExitStatus) -> ExitCode {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from)
}

/// Verifies clap's command definition during unit tests and CI.
pub fn verify_cli_definition() {
    Cli::command().debug_assert();
}

fn exit_code_from_i32(code: i32) -> ExitCode {
    u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from)
}

fn write_stdout(message: &str) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{message}")
}

fn write_stderr(message: &str) -> io::Result<()> {
    writeln!(io::stderr().lock(), "{message}")
}

fn is_explicit_confirmation(input: &str) -> bool {
    let input = input.strip_suffix('\n').unwrap_or(input);
    let input = input.strip_suffix('\r').unwrap_or(input);
    input == "yes"
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn clap_definition_is_valid() {
        verify_cli_definition();
    }

    #[test]
    fn json_flag_is_global() {
        let before = Cli::try_parse_from(["calcifer", "--json", "doctor"]);
        let after = Cli::try_parse_from(["calcifer", "doctor", "--json"]);

        assert!(before.is_ok());
        assert!(after.is_ok());
    }

    #[test]
    fn unimplemented_commands_fail_closed() {
        for command in ["switch", "use"] {
            let result = Cli::try_parse_from(["calcifer", command]);
            assert!(result.is_err(), "{command} must remain unavailable");
        }
    }

    #[test]
    fn update_check_has_strict_optional_channels() {
        assert!(Cli::try_parse_from(["calcifer", "update", "check"]).is_ok());
        assert!(
            Cli::try_parse_from(["calcifer", "update", "check", "--channel", "stable",]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["calcifer", "update", "check", "--channel", "preview",]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["calcifer", "update", "check", "--channel", "nightly",]).is_err()
        );
    }

    #[test]
    fn untracked_mode_requires_an_explicit_profile_without_a_thread_id() {
        assert!(Cli::try_parse_from(["calcifer", "run", "--untracked", "codex@work"]).is_ok());
        assert!(Cli::try_parse_from(["calcifer", "resume", "--untracked", "codex@work"]).is_ok());
        assert!(Cli::try_parse_from(["calcifer", "resume", "--untracked"]).is_err());
        assert!(
            Cli::try_parse_from([
                "calcifer",
                "resume",
                "--untracked",
                "codex@work",
                "01900000-0000-7000-8000-000000000001",
            ])
            .is_err()
        );

        let passthrough =
            Cli::try_parse_from(["calcifer", "run", "codex@work", "--", "--untracked"]);
        assert!(
            passthrough.is_ok(),
            "provider arguments after -- must remain opaque"
        );
        let Ok(passthrough) = passthrough else {
            return;
        };
        match passthrough.command {
            Commands::Run {
                untracked,
                provider_args,
                ..
            } => {
                assert!(!untracked);
                assert_eq!(provider_args, [OsString::from("--untracked")]);
            }
            _ => panic!("run command parsed as a different command"),
        }
    }

    #[test]
    fn removal_confirmation_accepts_only_exact_yes_with_a_terminal_line_ending() {
        for accepted in ["yes", "yes\n", "yes\r\n"] {
            assert!(is_explicit_confirmation(accepted), "{accepted:?}");
        }
        for rejected in ["", "y", "YES\n", " yes\n", "yes \n", "yes\n\n"] {
            assert!(!is_explicit_confirmation(rejected), "{rejected:?}");
        }
    }
}
